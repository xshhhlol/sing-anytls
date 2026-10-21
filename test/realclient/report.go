package realclient

import (
	"math"
	"sort"
)

// ShortRecordLength bounds records that can only carry bare control frames. A
// 7-byte AnyTLS FIN, SYNACK or heartbeat is a 24-byte TLS 1.3 record payload
// and a 31-byte TLS 1.2 AES-GCM record payload.
const ShortRecordLength = 64

// Stats summarizes a trace. Byte totals include TLS record headers.
type Stats struct {
	BytesUp     int64 `json:"bytes_up"`
	BytesDown   int64 `json:"bytes_down"`
	RecordsUp   int   `json:"records_up"`
	RecordsDown int   `json:"records_down"`
}

func (t Trace) Stats() Stats {
	var stats Stats
	for _, record := range t.Records {
		size := int64(record.Length + recordHeaderLen)
		if record.Direction == Upload {
			stats.BytesUp += size
			stats.RecordsUp++
		} else {
			stats.BytesDown += size
			stats.RecordsDown++
		}
	}
	return stats
}

// AppLengths returns the payload lengths of the first n application data
// records in one direction, or all of them if n <= 0.
func (t Trace) AppLengths(direction Direction, n int) []int {
	var lengths []int
	for _, record := range t.Records {
		if record.Type != RecordTypeApplicationData || record.Direction != direction {
			continue
		}
		if n > 0 && len(lengths) == n {
			break
		}
		lengths = append(lengths, record.Length)
	}
	return lengths
}

// Features returns the signed lengths of the first n application data records
// in both directions, positive for upload, zero-padded to n.
func (t Trace) Features(n int) []int {
	features := make([]int, 0, n)
	for _, record := range t.Records {
		if len(features) == n {
			break
		}
		if record.Type == RecordTypeApplicationData {
			features = append(features, int(record.Direction)*record.Length)
		}
	}
	for len(features) < n {
		features = append(features, 0)
	}
	return features
}

type Quantiles struct {
	Mean float64 `json:"mean"`
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
}

func NewQuantiles(values []float64) Quantiles {
	if len(values) == 0 {
		return Quantiles{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	var sum float64
	for _, value := range sorted {
		sum += value
	}
	at := func(fraction float64) float64 {
		return sorted[int(math.Ceil(fraction*float64(len(sorted))))-1]
	}
	return Quantiles{Mean: sum / float64(len(sorted)), P50: at(0.5), P90: at(0.9)}
}

// Shape describes the lengths of the first n application data records of one
// direction across connections. Fixed lengths show up as a high TopShare.
type Shape struct {
	Short     float64 `json:"short"`
	Distinct  float64 `json:"distinct"`
	TopLength int     `json:"top_length"`
	TopShare  float64 `json:"top_share"`
}

func NewShape(traces []Trace, direction Direction, n int) Shape {
	var shape Shape
	if len(traces) == 0 {
		return shape
	}
	counts := make(map[int]int)
	var total int
	for _, trace := range traces {
		lengths := trace.AppLengths(direction, n)
		distinct := make(map[int]struct{})
		for _, length := range lengths {
			if length <= ShortRecordLength {
				shape.Short++
			}
			distinct[length] = struct{}{}
			counts[length]++
			total++
		}
		shape.Distinct += float64(len(distinct))
	}
	shape.Short /= float64(len(traces))
	shape.Distinct /= float64(len(traces))
	for length, count := range counts {
		if count > counts[shape.TopLength] || count == counts[shape.TopLength] && length < shape.TopLength {
			shape.TopLength = length
		}
	}
	if total > 0 {
		shape.TopShare = float64(counts[shape.TopLength]) / float64(total)
	}
	return shape
}

// Summary describes a set of connections. Malformed traces are counted and
// excluded from the statistics.
type Summary struct {
	Connections int       `json:"connections"`
	Malformed   int       `json:"malformed"`
	BytesUp     Quantiles `json:"bytes_up"`
	BytesDown   Quantiles `json:"bytes_down"`
	TotalUp     int64     `json:"total_up"`
	TotalDown   int64     `json:"total_down"`
	Up          Shape     `json:"up"`
	Down        Shape     `json:"down"`
}

func Summarize(traces []Trace, n int) Summary {
	summary := Summary{Connections: len(traces)}
	valid := WellFormed(traces)
	summary.Malformed = len(traces) - len(valid)
	var up, down []float64
	for _, trace := range valid {
		stats := trace.Stats()
		up = append(up, float64(stats.BytesUp))
		down = append(down, float64(stats.BytesDown))
		summary.TotalUp += stats.BytesUp
		summary.TotalDown += stats.BytesDown
	}
	summary.BytesUp = NewQuantiles(up)
	summary.BytesDown = NewQuantiles(down)
	summary.Up = NewShape(valid, Upload, n)
	summary.Down = NewShape(valid, Download, n)
	return summary
}

func WellFormed(traces []Trace) []Trace {
	var valid []Trace
	for _, trace := range traces {
		if !trace.Malformed {
			valid = append(valid, trace)
		}
	}
	return valid
}

// Separability is the leave-one-out result of a 1-nearest-neighbor classifier
// separating two sets of connections by Features(n). Each connection is a
// single sample, so none is used as training and test data at once. It is a
// lab indicator of how distinct the record sequences are, not a DPI result:
// real classifiers also use timing, volume and many more connections.
type Separability struct {
	Accuracy      float64 `json:"accuracy"`
	Recall        float64 `json:"recall"`
	FalsePositive float64 `json:"false_positive"`
	Samples       [2]int  `json:"samples"`
}

func Separate(positive, negative []Trace, n int) Separability {
	positive, negative = WellFormed(positive), WellFormed(negative)
	result := Separability{Samples: [2]int{len(positive), len(negative)}}
	if len(positive) < 2 || len(negative) < 2 {
		return result
	}
	type sample struct {
		features []int
		positive bool
	}
	var samples []sample
	for _, trace := range positive {
		samples = append(samples, sample{trace.Features(n), true})
	}
	for _, trace := range negative {
		samples = append(samples, sample{trace.Features(n), false})
	}
	var correct, truePositive, falsePositive int
	for index, query := range samples {
		nearest := -1
		bestDistance := math.MaxInt
		for candidate, other := range samples {
			if candidate == index {
				continue
			}
			var distance int
			for feature := range query.features {
				difference := query.features[feature] - other.features[feature]
				distance += max(difference, -difference)
			}
			if distance < bestDistance {
				bestDistance, nearest = distance, candidate
			}
		}
		predicted := samples[nearest].positive
		if predicted == query.positive {
			correct++
		}
		if predicted && query.positive {
			truePositive++
		}
		if predicted && !query.positive {
			falsePositive++
		}
	}
	result.Accuracy = float64(correct) / float64(len(samples))
	result.Recall = float64(truePositive) / float64(len(positive))
	result.FalsePositive = float64(falsePositive) / float64(len(negative))
	return result
}
