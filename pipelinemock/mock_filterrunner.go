// Automatically generated by MockGen. DO NOT EDIT!
// Source: heka/pipeline (interfaces: FilterRunner)

package pipelinemock

import (
	pipeline "heka/pipeline"
	sync "sync"
	time "time"
	gomock "github.com/rafrombrc/gomock/gomock"
)

// Mock of FilterRunner interface
type MockFilterRunner struct {
	ctrl     *gomock.Controller
	recorder *_MockFilterRunnerRecorder
}

// Recorder for MockFilterRunner (not exported)
type _MockFilterRunnerRecorder struct {
	mock *MockFilterRunner
}

func NewMockFilterRunner(ctrl *gomock.Controller) *MockFilterRunner {
	mock := &MockFilterRunner{ctrl: ctrl}
	mock.recorder = &_MockFilterRunnerRecorder{mock}
	return mock
}

func (_m *MockFilterRunner) EXPECT() *_MockFilterRunnerRecorder {
	return _m.recorder
}

func (_m *MockFilterRunner) BackPressured() bool {
	ret := _m.ctrl.Call(_m, "BackPressured")
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) BackPressured() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "BackPressured")
}

func (_m *MockFilterRunner) Filter() pipeline.Filter {
	ret := _m.ctrl.Call(_m, "Filter")
	ret0, _ := ret[0].(pipeline.Filter)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) Filter() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Filter")
}

func (_m *MockFilterRunner) InChan() chan *pipeline.PipelinePack {
	ret := _m.ctrl.Call(_m, "InChan")
	ret0, _ := ret[0].(chan *pipeline.PipelinePack)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) InChan() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "InChan")
}

func (_m *MockFilterRunner) Inject(_param0 *pipeline.PipelinePack) bool {
	ret := _m.ctrl.Call(_m, "Inject", _param0)
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) Inject(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Inject", arg0)
}

func (_m *MockFilterRunner) IsStoppable() bool {
	ret := _m.ctrl.Call(_m, "IsStoppable")
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) IsStoppable() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "IsStoppable")
}

func (_m *MockFilterRunner) LeakCount() int {
	ret := _m.ctrl.Call(_m, "LeakCount")
	ret0, _ := ret[0].(int)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) LeakCount() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "LeakCount")
}

func (_m *MockFilterRunner) LogError(_param0 error) {
	_m.ctrl.Call(_m, "LogError", _param0)
}

func (_mr *_MockFilterRunnerRecorder) LogError(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "LogError", arg0)
}

func (_m *MockFilterRunner) LogMessage(_param0 string) {
	_m.ctrl.Call(_m, "LogMessage", _param0)
}

func (_mr *_MockFilterRunnerRecorder) LogMessage(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "LogMessage", arg0)
}

func (_m *MockFilterRunner) MatchRunner() *pipeline.MatchRunner {
	ret := _m.ctrl.Call(_m, "MatchRunner")
	ret0, _ := ret[0].(*pipeline.MatchRunner)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) MatchRunner() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "MatchRunner")
}

func (_m *MockFilterRunner) Name() string {
	ret := _m.ctrl.Call(_m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) Name() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Name")
}

func (_m *MockFilterRunner) OldFilter() pipeline.OldFilter {
	ret := _m.ctrl.Call(_m, "OldFilter")
	ret0, _ := ret[0].(pipeline.OldFilter)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) OldFilter() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "OldFilter")
}

func (_m *MockFilterRunner) Plugin() pipeline.Plugin {
	ret := _m.ctrl.Call(_m, "Plugin")
	ret0, _ := ret[0].(pipeline.Plugin)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) Plugin() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Plugin")
}

func (_m *MockFilterRunner) RetainPack(_param0 *pipeline.PipelinePack) {
	_m.ctrl.Call(_m, "RetainPack", _param0)
}

func (_mr *_MockFilterRunnerRecorder) RetainPack(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RetainPack", arg0)
}

func (_m *MockFilterRunner) SetLeakCount(_param0 int) {
	_m.ctrl.Call(_m, "SetLeakCount", _param0)
}

func (_mr *_MockFilterRunnerRecorder) SetLeakCount(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SetLeakCount", arg0)
}

func (_m *MockFilterRunner) SetName(_param0 string) {
	_m.ctrl.Call(_m, "SetName", _param0)
}

func (_mr *_MockFilterRunnerRecorder) SetName(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SetName", arg0)
}

func (_m *MockFilterRunner) Start(_param0 pipeline.PluginHelper, _param1 *sync.WaitGroup) error {
	ret := _m.ctrl.Call(_m, "Start", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) Start(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Start", arg0, arg1)
}

func (_m *MockFilterRunner) StopChan() chan bool {
	ret := _m.ctrl.Call(_m, "StopChan")
	ret0, _ := ret[0].(chan bool)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) StopChan() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "StopChan")
}

func (_m *MockFilterRunner) Ticker() <-chan time.Time {
	ret := _m.ctrl.Call(_m, "Ticker")
	ret0, _ := ret[0].(<-chan time.Time)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) Ticker() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Ticker")
}

func (_m *MockFilterRunner) Unregister(_param0 *pipeline.PipelineConfig) error {
	ret := _m.ctrl.Call(_m, "Unregister", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) Unregister(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Unregister", arg0)
}

func (_m *MockFilterRunner) UpdateCursor(_param0 string) {
	_m.ctrl.Call(_m, "UpdateCursor", _param0)
}

func (_mr *_MockFilterRunnerRecorder) UpdateCursor(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "UpdateCursor", arg0)
}

func (_m *MockFilterRunner) UsesBuffering() bool {
	ret := _m.ctrl.Call(_m, "UsesBuffering")
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockFilterRunnerRecorder) UsesBuffering() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "UsesBuffering")
}
