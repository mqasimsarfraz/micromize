package operators

import (
	"context"
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

// DataOperator is an alias for igoperators.DataOperator to avoid direct dependency in main
type DataOperator = igoperators.DataOperator

func NewLocalManager() (igoperators.DataOperator, error) {
	host.Init(host.Config{})
	localManagerOp := localmanager.LocalManagerOperator
	localManagerParams := localManagerOp.GlobalParamDescs().ToParams()

	if err := localManagerOp.Init(localManagerParams); err != nil {
		return nil, fmt.Errorf("init local manager: %w", err)
	}
	return localManagerOp, nil
}

// NewOCIHandler creates and returns the OCI handler operator
func NewOCIHandler() igoperators.DataOperator {
	return ocihandler.OciHandler
}

// NewCLIOperator creates and returns the CLI operator
func NewCLIOperator() igoperators.DataOperator {
	return clioperator.CLIOperator
}

// NewOtelLogOperator creates and returns the OpenTelemetry operator
func NewOtelLogOperator(endpoint string, insecure bool) (igoperators.DataOperator, error) {
	res, _ := resource.New(context.Background(), resource.WithAttributes(
		semconv.ServiceNameKey.String("micromize"),
	))

	var options []otlploggrpc.Option
	if insecure {
		options = append(options, otlploggrpc.WithInsecure())
	}
	options = append(options, otlploggrpc.WithEndpoint(endpoint))
	options = append(options, otlploggrpc.WithCompressor("gzip"))
	exp, err := otlploggrpc.New(context.Background(), options...)
	if err != nil {
		return nil, fmt.Errorf("creating otlp exporter: %w", err)
	}
	processor := sdklog.NewBatchProcessor(exp)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor), sdklog.WithResource(res))

	op := simple.New("otel-logs",
		simple.OnInit(func(gadgetCtx igoperators.GadgetContext) error {
			for _, ds := range gadgetCtx.GetDataSources() {
				logger := provider.Logger(ds.Name())
				ts := ds.GetField("timestamp_raw")

				ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
					var rec otellog.Record

					// set basic fields
					rec.SetBody(otellog.StringValue("Event Data from " + ds.Name()))
					rec.SetSeverity(9) // INFO
					if ts != nil {
						timestamp, err := ts.Int64(data)
						if err == nil {
							rec.SetObservedTimestamp(time.Unix(0, timestamp*int64(time.Microsecond)))
						}
					}
					// set fields as attributes
					attribs := make([]otellog.KeyValue, 0)
					for _, field := range ds.Fields() {
						// TODO: Should we support other types in datasouce.GetKeyValueFunc?
						if field.GetKind() == api.Kind_Invalid ||
							field.GetKind() == api.Kind_Bool ||
							field.GetKind() == api.Kind_Bytes {
							continue
						}
						acc := ds.GetField(field.GetFullName())
						kvf, err := datasource.GetKeyValueFunc[string, otellog.Value](acc, field.GetName(), otellog.Int64Value, otellog.Float64Value, otellog.StringValue)
						if err != nil {
							return fmt.Errorf("getting key/val func for %s: %w", field.GetName(), err)
						}
						key, val := kvf(data)
						kv := otellog.KeyValue{
							Key:   key,
							Value: val,
						}
						attribs = append(attribs, kv)
					}
					rec.AddAttributes(attribs...)

					logger.Emit(gadgetCtx.Context(), rec)
					return nil
				}, 10000)
			}
			return nil
		}),
	)

	return op, nil
}
