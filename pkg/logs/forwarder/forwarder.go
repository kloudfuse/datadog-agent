package forwarder

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/logs/auditor"
	"github.com/DataDog/datadog-agent/pkg/logs/client"
	"github.com/DataDog/datadog-agent/pkg/logs/client/http"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/logs/restart"
	"github.com/DataDog/datadog-agent/pkg/logs/sender"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"strings"
)

const (
	EventTypeDBMSample = "dbm-sample"
)

type EventPlatformForwarder interface {
	SendEventPlatformEvent(e *message.Message, eventType string) error
	Start()
	Stop()
}

type DefaultEventPlatformForwarder struct {
	pipelines       map[string]*PassthroughPipeline
	destinationsCtx *client.DestinationsContext
}

func (s *DefaultEventPlatformForwarder) SendEventPlatformEvent(e *message.Message, eventType string) error {
	p, ok := s.pipelines[eventType]
	if !ok {
		return fmt.Errorf("unknown event type: %s", eventType)
	}
	// TODO: is non-blocking write here a good idea? If an agent is monitoring a lot of databases might this get full?
	select {
	case p.in <- e:
		return nil
	default:
		return fmt.Errorf("pipeline channel for eventType %s is full", eventType)
	}
}

func (s *DefaultEventPlatformForwarder) Start() {
	s.destinationsCtx.Start()
	for _, p := range s.pipelines {
		p.Start()
	}
}

func (s *DefaultEventPlatformForwarder) Stop() {
	stopper := restart.NewParallelStopper()
	for _, p := range s.pipelines {
		stopper.Add(p)
	}
	stopper.Stop()
	// TODO: wait on stop and cancel context only after timeout like logs agent
	s.destinationsCtx.Stop()
}

type PassthroughPipeline struct {
	// TODO: do we need to parallelize sending? If a single agent has some massive number of checks is this necessary?
	sender  *sender.Sender
	in      chan *message.Message
	auditor auditor.Auditor
}

func NewHTTPPassthroughPipeline(endpoints *config.Endpoints, destinationsContext *client.DestinationsContext) (p *PassthroughPipeline, err error) {
	if !endpoints.UseHTTP {
		return p, fmt.Errorf("endpoints must be http")
	}
	main := http.NewDestination(endpoints.Main, http.JSONContentType, destinationsContext)
	additionals := []client.Destination{}
	for _, endpoint := range endpoints.Additionals {
		additionals = append(additionals, http.NewDestination(endpoint, http.JSONContentType, destinationsContext))
	}
	destinations := client.NewDestinations(main, additionals)
	inputChan := make(chan *message.Message, config.ChanSize)
	strategy := sender.NewBatchStrategy(sender.ArraySerializer, endpoints.BatchWait)
	a := auditor.NewNullAuditor()
	return &PassthroughPipeline{
		sender:  sender.NewSender(inputChan, a.Channel(), destinations, strategy),
		in:      inputChan,
		auditor: a,
	}, nil
}

func (p *PassthroughPipeline) Start() {
	p.auditor.Start()
	p.sender.Start()
}

func (p *PassthroughPipeline) Stop() {
	p.sender.Stop()
	p.auditor.Stop()
}

func joinHosts(endpoints []config.Endpoint) string {
	var additionalHosts []string
	for _, e := range endpoints {
		additionalHosts = append(additionalHosts, e.Host)
	}
	return strings.Join(additionalHosts, ",")
}

func newDbmSamplesPipeline(destinationsContext *client.DestinationsContext) (eventType string, p *PassthroughPipeline, err error) {
	eventType = EventTypeDBMSample
	
	configKeys := config.LogsConfigKeys{
		CompressionLevel:        "database_monitoring.samples.compression_level",
		ConnectionResetInterval: "database_monitoring.samples.connection_reset_interval",
		LogsDDURL:               "database_monitoring.samples.logs_dd_url",
		DDURL:                   "database_monitoring.samples.dd_url",
		DevModeNoSSL:            "database_monitoring.samples.dev_mode_no_ssl",
		AdditionalEndpoints:     "database_monitoring.samples.additional_endpoints",
		BatchWait:               "database_monitoring.samples.batch_wait",
	}
	
	endpoints, err := config.BuildHTTPEndpointsWithConfig(configKeys, "dbquery-http-intake.logs.")
	if err != nil {
		return eventType, nil, err
	}

	p, err = NewHTTPPassthroughPipeline(endpoints, destinationsContext)
	if err != nil {
		return eventType, nil, err
	}

	log.Debugf("Initialized event platform forwarder pipeline. eventType=%s mainHost=%s additionalHosts=%s", EventTypeDBMSample, endpoints.Main.Host, joinHosts(endpoints.Additionals))

	return eventType, p, nil
}

func NewEventPlatformForwarder() EventPlatformForwarder {
	destinationsCtx := client.NewDestinationsContext()
	destinationsCtx.Start()
	pipelines := make(map[string]*PassthroughPipeline)

	eventType, p, err := newDbmSamplesPipeline(destinationsCtx)
	if err != nil {
		log.Errorf("Failed to initialize event platform forwarder pipeline. eventType=%s, error=%s", eventType, err.Error())
	} else {
		pipelines[eventType] = p
	}

	// dbm-metrics

	return &DefaultEventPlatformForwarder{
		pipelines:       pipelines,
		destinationsCtx: destinationsCtx,
	}
}
