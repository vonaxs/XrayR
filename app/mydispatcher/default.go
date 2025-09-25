package mydispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/vonaxs/XrayR/common/counter"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	routingSession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var errSniffingTimeout = newError("timeout on sniffing")

type cachedReader struct {
	sync.Mutex
	reader *pipe.Reader
	cache  buf.MultiBuffer
}

func (r *cachedReader) Cache(b *buf.Buffer) {
	mb, _ := r.reader.ReadMultiBufferTimeout(time.Millisecond * 100)
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	rawBytes := b.Extend(buf.Size)
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBufferTimeout(timeout)
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	r.reader.Interrupt()
}

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
    ohm     outbound.Manager
    router  routing.Router
    policy  policy.Manager
    stats   stats.Manager
    dns     dns.Client
    fdns    dns.FakeDNSEngine

    Counter *counter.Manager   // ✅ 新增，管理用户流量统计
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dc dns.Client) error {
			core.OptionalFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				d.fdns = fdns
			})
			return d.Init(config.(*Config), om, router, pm, sm, dc)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dns dns.Client) error {
    d.ohm = om
    d.router = router
    d.policy = pm
    d.stats = sm
    d.dns = dns
    d.Counter = counter.NewManager()   // ✅ 初始化计数器
    return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error {
	return nil
}

func (d *DefaultDispatcher) getLink(ctx context.Context) (*transport.Link, *transport.Link, error) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		// ✅ 强制关闭 splice，避免 Vision 模式绕过统计
		sessionInbound.CanSpliceCopy = 3
		user = sessionInbound.User
	}

	if user != nil && len(user.Email) > 0 {
		ts := d.Counter.GetCounter(user.Email)

		// uplink
		inboundLink.Writer = &SizeStatWriter{
			Writer:  inboundLink.Writer,
			Counter: ts.UpCounter,
		}

		// downlink
		outboundLink.Writer = &SizeStatWriter{
			Writer:  outboundLink.Writer,
			Counter: ts.DownCounter,
		}
	}


	return inboundLink, outboundLink, nil
}

func (d *DefaultDispatcher) shouldOverride(ctx context.Context, result SniffResult, request session.SniffingRequest, destination net.Destination) bool {
	domain := result.Domain()
	for _, d := range request.ExcludeForDomain {
		if strings.ToLower(domain) == d {
			return false
		}
	}
	protocolString := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		protocolString = resComp.ProtocolForDomainResult()
	}
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.HasPrefix(protocolString, p) || strings.HasPrefix(p, protocolString) {
			return true
		}
		if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && protocolString != "bittorrent" && p == "fakedns" &&
			destination.Address.Family().IsIP() && fkr0.IsIPInIPPool(destination.Address) {
			errors.LogInfo(ctx, "Using sniffer ", protocolString, " since the fake DNS missed")
			return true
		}
		if resultSubset, ok := result.(SnifferIsProtoSubsetOf); ok {
			if resultSubset.IsProtoSubsetOf(p) {
				return true
			}
		}
	}

	return false
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	sniffingRequest := content.SniffingRequest
	inbound, outbound, err := d.getLink(ctx)
	if err != nil {
		return nil, err
	}
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func() {
			cReader := &cachedReader{
				reader: outbound.Reader.(*pipe.Reader),
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = net.ParseAddress(domain)
				if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}()
	}
	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return newError("Dispatcher: Invalid destination.")
	}

	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	// ✅ 新增：流量统计包装
	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		sessionInbound.CanSpliceCopy = 3 // 禁用 splice，避免 Vision 下行绕过
		user = sessionInbound.User
	}
	if user != nil && len(user.Email) > 0 {
		ts := d.Counter.GetCounter(user.Email)

		// uplink
		outbound.Reader = &CounterReader{
			Reader:  outbound.Reader,
			Counter: ts.UpCounter,   // ✅ 去掉 &，直接传指针
		}

		// downlink
		outbound.Writer = &SizeStatWriter{
			Writer:  outbound.Writer,
			Counter: ts.DownCounter, // ✅ 去掉 &
		}
	}

	// ✅ 保留原本 sniffing / routedDispatch 逻辑
	sniffingRequest := content.SniffingRequest
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func() {
			cReader := &cachedReader{
				reader: outbound.Reader.(*pipe.Reader),
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = net.ParseAddress(domain)
				if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}()
	}

	return nil
}

// 统计 reader（uplink）
type CounterReader struct {
    Reader  buf.Reader
    Counter *counter.XrayTrafficCounter
}

func (r *CounterReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
    mb, err := r.Reader.ReadMultiBuffer()
    if !mb.IsEmpty() && r.Counter != nil {
        r.Counter.Add(int64(mb.Len()))
    }
    return mb, err
}

// 统计 writer（downlink）
type SizeStatWriter struct {
    Writer  buf.Writer
    Counter *counter.XrayTrafficCounter
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
    if !mb.IsEmpty() && w.Counter != nil {
        w.Counter.Add(int64(mb.Len()))
    }
    return w.Writer.WriteMultiBuffer(mb)
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network) (SniffResult, error) {
	payload := buf.New()
	defer payload.Release()

	sniffer := NewSniffer(ctx)

	metaresult, metadataErr := sniffer.SniffMetadata(ctx)

	if metadataOnly {
		return metaresult, metadataErr
	}

	contentResult, contentErr := func() (SniffResult, error) {
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				totalAttempt++
				if totalAttempt > 2 {
					return nil, errSniffingTimeout
				}

				cReader.Cache(payload)
				if !payload.IsEmpty() {
					result, err := sniffer.Sniff(ctx, payload.Bytes(), network)
					if err != common.ErrNoClue {
						return result, err
					}
				}
				if payload.IsFull() {
					return nil, errUnknownContent
				}
			}
		}
	}()
	if contentErr != nil && metadataErr == nil {
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		return CompositeResult(metaresult, contentResult), nil
	}
	return contentResult, contentErr
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if hosts, ok := d.dns.(dns.HostsLookup); ok && destination.Address.Family().IsDomain() {
		proxied := hosts.LookupHosts(ob.Target.String())
		if proxied != nil {
			ro := ob.RouteTarget == destination
			destination.Address = *proxied
			if ro {
				ob.RouteTarget = destination
			} else {
				ob.Target = destination
			}
		}
	}

	var handler outbound.Handler



	routingLink := routingSession.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0
	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			isPickRoute = 1
			errors.LogInfo(ctx, "taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]")
			handler = h
		} else {
			errors.LogError(ctx, "non existing tag for platform initialized detour: ", forcedOutboundTag)
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			outTag := route.GetOutboundTag()
			if h := d.ohm.GetHandler(outTag); h != nil {
				isPickRoute = 2
				errors.LogInfo(ctx, "taking detour [", outTag, "] for [", destination, "]")
				handler = h
			} else {
				errors.LogWarning(ctx, "non existing outTag: ", outTag)
			}
		} else {
			errors.LogInfo(ctx, "default route for ", destination)
		}
	}

	if handler == nil {
		handler = d.ohm.GetHandler(inTag) // Default outbound handler tag should be as same as the inbound tag
	}

	// If there is no outbound with tag as same as the inbound tag
	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if handler == nil {
		errors.LogInfo(ctx, "default outbound handler not exist")
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}

	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			if inTag == "" {
				accessMessage.Detour = tag
			} else if isPickRoute == 1 {
				accessMessage.Detour = inTag + " ==> " + tag
			} else if isPickRoute == 2 {
				accessMessage.Detour = inTag + " -> " + tag
			} else {
				accessMessage.Detour = inTag + " >> " + tag
			}
		}
		log.Record(accessMessage)
	}

	handler.Dispatch(ctx, link)
}
