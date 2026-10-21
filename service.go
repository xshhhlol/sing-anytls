package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ServiceOptions struct {
	// TrafficShaping is opt-in. With no explicit PaddingScheme it also advertises
	// a variable-length upload policy using the existing policy update command.
	TrafficShaping *TrafficShapingOptions
	// HandshakeTimeout bounds authentication and its padding reads. Zero uses
	// 10 seconds. A short unauthenticated request is handed to FallbackHandler
	// after EOF or this timeout; it is never compared to a partial password.
	HandshakeTimeout time.Duration
	PaddingScheme    []byte
	Handler          N.TCPConnectionHandlerEx
	FallbackHandler  N.TCPConnectionHandlerEx
	Logger           logger.ContextLogger
}

type Service struct {
	trafficShaping   *TrafficShapingOptions
	handshakeTimeout time.Duration
	password         [passwordLen]byte
	padding          common.TypedValue[*paddingFactory]
	handler          N.TCPConnectionHandlerEx
	fallbackHandler  N.TCPConnectionHandlerEx
	logger           logger.ContextLogger
}

func newService(options ServiceOptions) (*Service, error) {
	if options.HandshakeTimeout < 0 {
		return nil, E.New("anytls: negative handshake timeout")
	}
	if options.HandshakeTimeout == 0 {
		options.HandshakeTimeout = 10 * time.Second
	}
	shaping, err := normalizeTrafficShaping(options.TrafficShaping)
	if err != nil {
		return nil, err
	}
	paddingScheme := options.PaddingScheme
	if len(paddingScheme) == 0 {
		if shaping != nil {
			paddingScheme = shaping.clientPaddingScheme()
		} else {
			paddingScheme = DefaultPaddingScheme
		}
	}
	factory, err := newPaddingFactory(paddingScheme)
	if err != nil {
		return nil, err
	}
	service := &Service{
		trafficShaping:   shaping,
		handshakeTimeout: options.HandshakeTimeout,
		handler:          options.Handler,
		fallbackHandler:  options.FallbackHandler,
		logger:           options.Logger,
	}
	if service.logger == nil {
		service.logger = logger.NOP()
	}
	service.padding.Store(factory)
	return service, nil
}

func NewService(password string, options ServiceOptions) (*Service, error) {
	service, err := newService(options)
	if err != nil {
		return nil, err
	}
	service.password = sha256.Sum256([]byte(password))
	return service, nil
}

func (s *Service) UpdatePaddingScheme(rawScheme []byte) error {
	factory, err := newPaddingFactory(rawScheme)
	if err != nil {
		return err
	}
	s.padding.Store(factory)
	return nil
}

// Authentication operates on a byte stream, independently of TLS record and TCP
// read boundaries. No partial password is examined: early rejection by matching
// prefixes would expose an oracle for the reusable authentication verifier.
func (s *Service) handleConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc, authenticate func(password []byte) (context.Context, bool)) error {
	if err := ctx.Err(); err != nil {
		conn.Close()
		return err
	}
	deadline := time.Now().Add(s.handshakeTimeout)
	if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	err := conn.SetReadDeadline(deadline)
	if err != nil {
		conn.Close()
		return E.Cause(err, "anytls: set handshake deadline")
	}
	canceled := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		conn.SetReadDeadline(time.Now())
		close(canceled)
	})
	buffer := buf.NewSize(passwordLen)
	serveContext, authenticated, handshakeErr := func() (context.Context, bool, error) {
		_, readErr := buffer.ReadFullFrom(conn, passwordLen)
		if readErr != nil {
			return nil, false, readErr
		}
		serveContext, authenticated := authenticate(buffer.Bytes())
		if !authenticated {
			return nil, false, ErrAuthentication
		}
		return serveContext, true, readAuthenticationPadding(conn)
	}()
	// Synchronize an already-running cancellation callback before removing the
	// deadline. It must never leave an expired deadline on a fallback or session.
	if !stopCancellation() {
		<-canceled
	}
	clearErr := conn.SetReadDeadline(time.Time{})
	if err = ctx.Err(); err != nil {
		buffer.Release()
		conn.Close()
		return err
	}
	if clearErr != nil {
		buffer.Release()
		conn.Close()
		return E.Cause(clearErr, "anytls: clear handshake deadline")
	}
	if !authenticated {
		// Replay every consumed byte, including a partial read ending with EOF or
		// timeout. The cached connection owns a reference until drained or closed.
		cachedConn := bufio.NewCachedConn(conn, buffer)
		buffer.Release()
		return s.fallback(ctx, cachedConn, source, E.Errors(ErrAuthentication, handshakeErr), onClose)
	}
	buffer.Release()
	if handshakeErr != nil {
		conn.Close()
		return handshakeErr
	}
	return s.serve(serveContext, conn, source, onClose)
}

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	return s.handleConnection(ctx, conn, source, onClose, func(password []byte) (context.Context, bool) {
		if subtle.ConstantTimeCompare(password, s.password[:]) != 1 {
			return nil, false
		}
		return ctx, true
	})
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, cause error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		conn.Close()
		return E.Errors(cause, ErrFallbackClosed)
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}

func readAuthenticationPadding(conn net.Conn) error {
	var paddingLenBytes [2]byte
	_, err := io.ReadFull(conn, paddingLenBytes[:])
	if err != nil {
		return E.Cause(err, "anytls: read padding length")
	}
	paddingLen := int(binary.BigEndian.Uint16(paddingLenBytes[:]))
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, conn, int64(paddingLen))
		if err != nil {
			return E.Cause(err, "anytls: read padding")
		}
	}
	return nil
}

func (s *Service) serve(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	serving := newServerSession(ctx, s, conn, source)
	err := serving.readLoop()
	serving.Close()
	if E.IsClosedOrCanceled(err) {
		err = nil
	} else {
		s.logger.DebugContext(ctx, E.Cause(err, "anytls: session closed"))
	}
	if onClose != nil {
		onClose(err)
	}
	return nil
}

func (s *Service) acceptStream(parent *session, accepted *stream) {
	ctx := parent.serviceContext
	destination, err := M.SocksaddrSerializer.ReadAddrPort(accepted)
	if err != nil {
		if !E.IsClosedOrCanceled(err) {
			s.logger.ErrorContext(ctx, E.Cause(err, "anytls: read destination"))
		}
		N.CloseOnHandshakeFailure(accepted, nil, err)
		return
	}
	s.handler.NewConnectionEx(ctx, accepted, parent.source, destination, nil)
}

type MultiService[U comparable] struct {
	*Service
	users common.TypedValue[map[[passwordLen]byte]U]
}

func NewMultiService[U comparable](options ServiceOptions) (*MultiService[U], error) {
	service, err := newService(options)
	if err != nil {
		return nil, err
	}
	multiService := &MultiService[U]{Service: service}
	multiService.users.Store(make(map[[passwordLen]byte]U))
	return multiService, nil
}

func (s *MultiService[U]) UpdateUsers(users []U, passwords []string) error {
	if len(users) != len(passwords) {
		return E.New("anytls: user and password counts differ")
	}
	userMap := make(map[[passwordLen]byte]U, len(users))
	for index, user := range users {
		userMap[sha256.Sum256([]byte(passwords[index]))] = user
	}
	s.users.Store(userMap)
	return nil
}

func (s *MultiService[U]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	return s.handleConnection(ctx, conn, source, onClose, func(password []byte) (context.Context, bool) {
		user, loaded := s.users.Load()[[passwordLen]byte(password)]
		if !loaded {
			return nil, false
		}
		return auth.ContextWithUser(ctx, user), true
	})
}
