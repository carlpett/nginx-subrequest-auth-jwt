package logger

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger interface {
	Debugw(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
	Fatalw(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
}

type loggerImpl struct {
	z *zap.SugaredLogger
}

func (dl *loggerImpl) Debugw(msg string, keysAndValues ...interface{}) {
	dl.z.Debugw(msg, keysAndValues...)
}

func (dl *loggerImpl) Infow(msg string, keysAndValues ...interface{}) {
	dl.z.Infow(msg, keysAndValues...)
}

func (dl *loggerImpl) Errorw(msg string, keysAndValues ...interface{}) {
	dl.z.Errorw(msg, keysAndValues...)
}

func (dl *loggerImpl) Fatalw(msg string, keysAndValues ...interface{}) {
	dl.z.Fatalw(msg, keysAndValues...)
}

func (dl *loggerImpl) Warnw(msg string, keysAndValues ...interface{}) {
	dl.z.Warnw(msg, keysAndValues...)
}

func NewLogger(lvl string) Logger {
	var level zapcore.Level
	unrecognizedLevel := false
	switch strings.ToLower(lvl) {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	case "fatal":
		level = zapcore.FatalLevel
	case "": // If not set, use info
		level = zapcore.InfoLevel
	default: // If set to something we don't recognize, set to info and warn
		level = zapcore.InfoLevel
		unrecognizedLevel = true
	}

	consoleDebugging := zapcore.Lock(os.Stdout)
	consoleErrors := zapcore.Lock(os.Stderr)

	highPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.ErrorLevel
	})
	lowPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl < zapcore.ErrorLevel && lvl >= level
	})

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), consoleErrors, highPriority),
		zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), consoleDebugging, lowPriority),
	)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	defer logger.Sync()

	l := &loggerImpl{
		z: logger.Sugar(),
	}
	if unrecognizedLevel {
		l.Warnw("Unrecognized value of log level, defaulting to info", "level", lvl)
	}

	return l
}
