/***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2012-2015
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Mike Trinkala (trink@mozilla.com)
#   Rob Miller (rmiller@mozilla.com)
#
# ***** END LICENSE BLOCK *****/
package tengo

import (
	"context"
	"errors"
	"fmt"
	"github.com/d5/tengo/v2"
	"log"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/pborman/uuid"
	"heka/message"
	"heka/pipeline"
	"heka/sandbox"
)

const SandboxIoTemplate = `{
memory_limit = %d,
instruction_limit = %d,
output_limit = %d,
path = [[%s]],
cpath = [[%s]],
remove_entries = {
[''] = { 'dofile', 'load', 'loadfile','loadstring', 'print'},
os = {'exit', 'setlocale'}}}`

const SandboxTemplate = `{
memory_limit = %d,
instruction_limit = %d,
output_limit = %d,
path = [[%s]],
cpath = [[%s]],
remove_entries = {
[''] = {'collectgarbage','coroutine','dofile','load','loadfile','loadstring','newproxy','print'},
os = {'getenv','execute','exit','remove','rename','setlocale','tmpname'}
},
disable_modules = {io = 1}
}`

func extractTengoFieldName(wrapped string) (fn string, found bool) {
	if l := len(wrapped); l > 0 && wrapped[l-1] == ']' {
		if strings.HasPrefix(wrapped, "Fields[") {
			fn = wrapped[7 : l-1]
			found = true
		}
	}
	return
}

func lookup_field(msg *message.Message, fn string, fi, ai int) (int,
	unsafe.Pointer, int) {

	var field *message.Field
	if fi != 0 {
		fields := msg.FindAllFields(fn)
		if fi >= len(fields) {
			return 0, unsafe.Pointer(nil), 0
		}
		field = fields[fi]
	} else {
		if field = msg.FindFirstField(fn); field == nil {
			return 0, unsafe.Pointer(nil), 0
		}
	}
	fieldType := int(field.GetValueType())
	switch field.GetValueType() {
	case message.Field_STRING:
		if ai >= len(field.ValueString) {
			break
		}
		value := field.ValueString[ai]
		return fieldType, unsafe.Pointer(&value), len(value)
	case message.Field_BYTES:
		if ai >= len(field.ValueBytes) {
			break
		}
		value := field.ValueBytes[ai]
		valueLen := len(value)
		if valueLen == 0 {
			break
		}
		return fieldType, unsafe.Pointer(&field.ValueBytes[ai][0]), valueLen
	case message.Field_INTEGER:
		if ai >= len(field.ValueInteger) {
			break
		}
		return fieldType, unsafe.Pointer(&field.ValueInteger[ai]), 0
	case message.Field_DOUBLE:
		if ai >= len(field.ValueDouble) {
			break
		}
		return fieldType, unsafe.Pointer(&field.ValueDouble[ai]), 0
	case message.Field_BOOL:
		if ai >= len(field.ValueBool) {
			break
		}
		return fieldType, unsafe.Pointer(&field.ValueBool[ai]), 0
	}
	return 0, unsafe.Pointer(nil), 0
}

// Enforces field and array index limits.
func write_to_field(msg *message.Message, fn string, value interface{}, rep string,
	fi, ai int) error {

	var field *message.Field
	fields := msg.FindAllFields(fn)

	// We're only allowed to modify existing fields or extend the field length
	// by one.
	if fi > len(fields) {
		return errors.New("bad field index")
	}

	if fi == len(fields) {
		// `fi == len(fields)` ==> we're creating a new field. Only array index
		// of zero is allowed.
		if ai != 0 {
			return errors.New("bad array index")
		}

		var err error
		if field, err = message.NewField(fn, value, rep); err != nil {
			return fmt.Errorf("Can't create field: %s", err)
		}
		msg.AddField(field)
		return nil
	}

	// Getting this far means the field we've asked for already exists, check
	// that the type matches, and ensure that we're overwriting a previous
	// array value or are extending the array length by one before writing.
	field = fields[fi]
	switch field.GetValueType() {
	case message.Field_STRING:

		if ai > len(field.ValueString) {
			return errors.New("bad array index")
		}
		if ai == len(field.ValueString) {
			field.ValueString = append(field.ValueString, value.(string))
		} else {
			field.ValueString[ai] = value.(string)
		}
	case message.Field_BYTES:
		v, ok := value.([]byte)
		if !ok {
			return fmt.Errorf("type error, '%s' is a bytes field", field.GetName())
		}
		if ai > len(field.ValueBytes) {
			return errors.New("bad array index")
		}
		if ai == len(field.ValueBytes) {
			field.ValueBytes = append(field.ValueBytes, v)
		} else {
			field.ValueBytes[ai] = v
		}
	case message.Field_INTEGER:
		v, ok := value.(int32)
		if !ok {
			return fmt.Errorf("type error, '%s' is an integer field", field.GetName())
		}
		if ai > len(field.ValueInteger) {
			return errors.New("bad array index")
		}
		if ai == len(field.ValueInteger) {
			field.ValueInteger = append(field.ValueInteger, int64(v))
		} else {
			field.ValueInteger[ai] = int64(v)
		}
	case message.Field_DOUBLE:
		v, ok := value.(float64)
		if !ok {
			return fmt.Errorf("type error, '%s' is a double field", field.GetName())
		}
		if ai > len(field.ValueDouble) {
			return errors.New("bad array index")
		}
		if ai == len(field.ValueDouble) {
			field.ValueDouble = append(field.ValueDouble, v)
		} else {
			field.ValueDouble[ai] = v
		}
	case message.Field_BOOL:
		v, ok := value.(bool)
		if !ok {
			return fmt.Errorf("type error, '%s' is an boolean field", field.GetName())
		}
		if ai > len(field.ValueBool) {
			return errors.New("bad array index")
		}
		if ai == len(field.ValueBool) {
			field.ValueBool = append(field.ValueBool, v)
		} else {
			field.ValueBool[ai] = v
		}
	}
	field.Representation = &rep
	return nil
}

// Enforces field and array index limits.
func delete_field(msg *message.Message, fn string, fi, ai int, has_ai bool) error {

	var field *message.Field
	fields := msg.FindAllFields(fn)

	// If the field doesn't exist consider it a no-op.
	if len(fields) == 0 {
		return nil
	}
	if fi > len(fields)-1 {
		return errors.New("bad field index")
	}

	field = fields[fi]
	if has_ai {
		switch field.GetValueType() {
		case message.Field_STRING:
			if ai > len(field.ValueString)-1 {
				return errors.New("bad array index")
			} else {
				field.ValueString = append(field.ValueString[:ai], field.ValueString[ai+1:]...)
			}
		case message.Field_BYTES:
			if ai > len(field.ValueBytes)-1 {
				return errors.New("bad array index")
			} else {
				field.ValueBytes = append(field.ValueBytes[:ai], field.ValueBytes[ai+1:]...)
			}
		case message.Field_INTEGER:
			if ai > len(field.ValueInteger)-1 {
				return errors.New("bad array index")
			} else {
				field.ValueInteger = append(field.ValueInteger[:ai], field.ValueInteger[ai+1:]...)
			}
		case message.Field_DOUBLE:
			if ai > len(field.ValueDouble)-1 {
				return errors.New("bad array index")
			} else {
				field.ValueDouble = append(field.ValueDouble[:ai], field.ValueDouble[ai+1:]...)
			}
		case message.Field_BOOL:
			if ai > len(field.ValueBool)-1 {
				return errors.New("bad array index")
			} else {
				field.ValueBool = append(field.ValueBool[:ai], field.ValueBool[ai+1:]...)
			}
		}
	} else {
		msg.DeleteField(field)
	}
	return nil
}

func go_tengo_read_message(ptr unsafe.Pointer, c string, fi, ai int) (int, unsafe.Pointer,
	int) {
	var lsb *TengoSandbox = (*TengoSandbox)(ptr)
	if lsb.pack != nil {
		fieldName := c
		switch fieldName {
		case "Type":
			value := lsb.pack.Message.GetType()
			cs := &value // freed by the caller
			return int(message.Field_STRING), unsafe.Pointer(cs),
				len(value)
		case "Logger":
			value := lsb.pack.Message.GetLogger()
			cs := &value // freed by the caller
			return int(message.Field_STRING), unsafe.Pointer(cs),
				len(value)
		case "Payload":
			value := lsb.pack.Message.GetPayload()
			cs := &value // freed by the caller
			return int(message.Field_STRING), unsafe.Pointer(cs),
				len(value)
		case "EnvVersion":
			value := lsb.pack.Message.GetEnvVersion()
			cs := &value // freed by the caller
			return int(message.Field_STRING), unsafe.Pointer(cs),
				len(value)
		case "Hostname":
			value := lsb.pack.Message.GetHostname()
			cs := &value // freed by the caller
			return int(message.Field_STRING), unsafe.Pointer(cs),
				len(value)
		case "Uuid":
			value := lsb.pack.Message.GetUuidString()
			cs := &value // freed by the caller
			return int(message.Field_STRING), unsafe.Pointer(cs),
				len(value)
		case "Timestamp":
			return int(message.Field_INTEGER),
				unsafe.Pointer(lsb.pack.Message.Timestamp), 0
		case "Severity":
			return int(message.Field_INTEGER),
				unsafe.Pointer(lsb.pack.Message.Severity), 0
		case "Pid":
			return int(message.Field_INTEGER),
				unsafe.Pointer(lsb.pack.Message.Pid), 0
		case "raw":
			if len(lsb.pack.MsgBytes) > 0 {
				return int(message.Field_BYTES),
					unsafe.Pointer(&lsb.pack.MsgBytes[0]),
					len(lsb.pack.MsgBytes)
			}
		default:
			if fn, found := extractTengoFieldName(fieldName); found {
				return lookup_field(lsb.pack.Message, fn, fi, ai)
			}
		}
	}
	return 0, unsafe.Pointer(nil), 0
}

//export go_tengo_write_message_string
func go_tengo_write_message_string(ptr unsafe.Pointer, c, v, rep string,
	fi, ai int) int {

	var lsb *TengoSandbox = (*TengoSandbox)(ptr)
	if lsb.pack == nil {
		lsb.globals.LogMessage("go_tengo_write_message_string", "No sandbox pack.")
		return 1
	}
	lsb.pack.TrustMsgBytes = false
	if !lsb.messageCopied && lsb.sbConfig.PluginType == "encoder" {
		lsb.pack.Message = message.CopyMessage(lsb.pack.Message)
		lsb.messageCopied = true
	}

	fieldName := c
	switch fieldName {
	case "Type":
		lsb.pack.Message.SetType(v)
		return 0
	case "Logger":
		lsb.pack.Message.SetLogger(v)
		return 0
	case "Payload":
		lsb.pack.Message.SetPayload(v)
		return 0
	case "EnvVersion":
		lsb.pack.Message.SetEnvVersion(v)
		return 0
	case "Hostname":
		lsb.pack.Message.SetHostname(v)
		return 0
	case "Uuid":
		value := v
		var uuidBytes []byte
		if uuidBytes = uuid.Parse(value); uuidBytes == nil {
			lsb.globals.LogMessage("go_tengo_write_message_string",
				"Bad UUID string.")
			return 1
		}
		lsb.pack.Message.SetUuid(uuidBytes)
		return 0
	case "Timestamp":
		vStr := v
		// First make sure we have anything at all.
		if vStr == "" {
			lsb.globals.LogMessage("go_tengo_write_message_string",
				"Empty timestamp string.")
			return 1
		}
		// Next try UnixNano integer parsing.
		value, err := strconv.ParseInt(vStr, 0, 64)
		if err != nil {
			// If that fails, try ForgivingTimeParse string parsing. Note that
			// ForgivingTimeParse is slow and not nearly as forgiving as the
			// name implies, it's probably better to parse the timestamp in
			// Tengo.
			loc, _ := time.LoadLocation("UTC")
			var parsedTime time.Time
			parsedTime, err = message.ForgivingTimeParse("", vStr, loc)
			if err != nil {
				lsb.globals.LogMessage("go_tengo_write_message_string",
					"Can't parse timestamp string.")
				return 1
			}
			value = parsedTime.UnixNano()
		}
		lsb.pack.Message.SetTimestamp(value)
		return 0
	case "Severity":
		value, err := strconv.ParseInt(v, 0, 32)
		if err != nil {
			lsb.globals.LogMessage("go_tengo_write_message_string",
				"Can't parse severity value.")
			return 1
		}
		lsb.pack.Message.SetSeverity(int32(value))
		return 0
	case "Pid":
		value, err := strconv.ParseInt(v, 0, 32)
		if err != nil {
			lsb.globals.LogMessage("go_tengo_write_message_string",
				"Can't parse PID value.")
			return 1
		}
		lsb.pack.Message.SetPid(int32(value))
		return 0
	default:
		if fn, found := extractTengoFieldName(fieldName); found {
			if err := write_to_field(lsb.pack.Message, fn, v, rep, fi, ai); err != nil {
				lsb.globals.LogMessage("go_tengo_write_message_string", err.Error())
				return 1
			}
			return 0
		}
	}
	lsb.globals.LogMessage("go_tengo_write_message_string", "Bad field name.")
	return 1
}

//export go_tengo_write_message_double
func go_tengo_write_message_double(ptr unsafe.Pointer, c string, v float64, rep string,
	fi, ai int) int {

	fieldName := c
	var lsb *TengoSandbox = (*TengoSandbox)(ptr)
	if lsb.pack == nil {
		lsb.globals.LogMessage("go_tengo_write_message_double", "No sandbox pack.")
		return 1
	}
	lsb.pack.TrustMsgBytes = false
	if !lsb.messageCopied && lsb.sbConfig.PluginType == "encoder" {
		lsb.pack.Message = message.CopyMessage(lsb.pack.Message)
		lsb.messageCopied = true
	}

	switch fieldName {
	case "Severity":
		value := int32(v)
		lsb.pack.Message.SetSeverity(value)
		return 0
	case "Pid":
		value := int32(v)
		lsb.pack.Message.SetPid(value)
		return 0
	case "Timestamp":
		value := int64(v)
		lsb.pack.Message.SetTimestamp(value)
		return 0
	default:
		if fn, found := extractTengoFieldName(fieldName); found {
			value := float64(v)
			if err := write_to_field(lsb.pack.Message, fn, value, rep, fi, ai); err != nil {
				lsb.globals.LogMessage("go_tengo_write_message_double", err.Error())
				return 1
			}
			return 0
		}
	}
	lsb.globals.LogMessage("go_tengo_write_message_double", "Bad field name.")
	return 1
}

//export go_tengo_write_message_bool
func go_tengo_write_message_bool(ptr unsafe.Pointer, c string, v bool, rep string,
	fi, ai int) int {

	fieldName := c
	var lsb *TengoSandbox = (*TengoSandbox)(ptr)
	if lsb.pack == nil {
		lsb.globals.LogMessage("go_tengo_write_message_bool", "No sandbox pack.")
		return 1
	}
	lsb.pack.TrustMsgBytes = false
	if !lsb.messageCopied && lsb.sbConfig.PluginType == "encoder" {
		lsb.pack.Message = message.CopyMessage(lsb.pack.Message)
		lsb.messageCopied = true
	}

	if fn, found := extractTengoFieldName(fieldName); found {
		if err := write_to_field(lsb.pack.Message, fn, v, rep, fi, ai); err != nil {
			lsb.globals.LogMessage("go_tengo_write_message_bool", err.Error())
			return 1
		}
		return 0
	}
	lsb.globals.LogMessage("go_tengo_write_message_bool", "Bad field name.")
	return 1
}

//export go_tengo_delete_message_field
func go_tengo_delete_message_field(ptr unsafe.Pointer, c string, fi, ai int, has_ai bool) int {

	fieldName := c
	var lsb *TengoSandbox = (*TengoSandbox)(ptr)
	if lsb.pack == nil {
		lsb.globals.LogMessage("go_tengo_delete_message_field", "No sandbox pack.")
		return 1
	}
	lsb.pack.TrustMsgBytes = false
	if !lsb.messageCopied && lsb.sbConfig.PluginType == "encoder" {
		lsb.pack.Message = message.CopyMessage(lsb.pack.Message)
		lsb.messageCopied = true
	}

	if fn, found := extractTengoFieldName(fieldName); found {
		if err := delete_field(lsb.pack.Message, fn, fi, ai, has_ai); err != nil {
			lsb.globals.LogMessage("go_tengo_delete_message_field", err.Error())
			return 1
		}
		return 0
	}
	lsb.globals.LogMessage("go_tengo_delete_message_field", "Bad field name.")
	return 1
}

//export go_tengo_read_next_field
func go_tengo_read_next_field(ptr unsafe.Pointer) (int, unsafe.Pointer, int,
	unsafe.Pointer, int, unsafe.Pointer, int, int) {
	var (
		fieldType         int
		name              string
		namePtr           unsafe.Pointer
		nameLen           int
		representation    string
		representationPtr unsafe.Pointer
		representationLen int
		valuePtr          unsafe.Pointer
		valueLen          int
		fieldLen          int
	)
	var lsb *TengoSandbox = (*TengoSandbox)(ptr)
	if lsb.pack != nil && lsb.field < len(lsb.pack.Message.Fields) {
		field := lsb.pack.Message.Fields[lsb.field]
		lsb.field++

		fieldType = int(field.GetValueType())
		name = field.GetName()
		namePtr = unsafe.Pointer(&name) // freed by the caller
		nameLen = len(name)
		representation = field.GetRepresentation()
		representationPtr = unsafe.Pointer(&representation) // freed by the caller
		representationLen = len(representation)
		switch field.GetValueType() {
		case message.Field_STRING:
			fieldLen = len(field.ValueString)
			if fieldLen == 0 {
				break
			}
			value := field.ValueString[0]
			valuePtr = unsafe.Pointer(&value) // freed by the caller
			valueLen = len(value)
		case message.Field_BYTES:
			fieldLen = len(field.ValueBytes)
			if fieldLen == 0 {
				break
			}
			value := field.ValueBytes[0]
			valueLen = len(value)
			if valueLen == 0 {
				break
			}
			valuePtr = unsafe.Pointer(&field.ValueBytes[0][0])
		case message.Field_INTEGER:
			fieldLen = len(field.ValueInteger)
			if fieldLen == 0 {
				break
			}
			valuePtr = unsafe.Pointer(&field.ValueInteger[0])
		case message.Field_DOUBLE:
			fieldLen = len(field.ValueDouble)
			if fieldLen == 0 {
				break
			}
			valuePtr = unsafe.Pointer(&field.ValueDouble[0])
		case message.Field_BOOL:
			fieldLen = len(field.ValueBool)
			if fieldLen == 0 {
				break
			}
			valuePtr = unsafe.Pointer(&field.ValueBool[0])
		}
	}

	return fieldType, namePtr, nameLen, valuePtr, valueLen,
		representationPtr, representationLen, fieldLen
}

//export go_tengo_read_config
func go_tengo_read_config(ptr unsafe.Pointer, c string) (int, unsafe.Pointer, int) {
	name := c
	var lsb *TengoSandbox = (*TengoSandbox)(ptr)
	if lsb.config == nil {
		return 0, unsafe.Pointer(nil), 0
	}

	v := lsb.config[name]
	switch v.(type) {
	case string:
		s := v.(string)
		cs := &s // freed by the caller
		return int(message.Field_STRING), unsafe.Pointer(cs), len(s)
	case bool:
		b := v.(bool)
		return int(message.Field_BOOL), unsafe.Pointer(&b), 0
	case int64:
		d := float64(v.(int64))
		return int(message.Field_DOUBLE), unsafe.Pointer(&d), 0
	case float64:
		d := v.(float64)
		return int(message.Field_DOUBLE), unsafe.Pointer(&d), 0
	}
	return 0, unsafe.Pointer(nil), 0
}

func go_tengo_inject_message(ptr unsafe.Pointer, payload string,
	payload_len int, payload_type, payload_name string) int {
	var lsb *TengoSandbox = (*TengoSandbox)(ptr)
	return lsb.injectMessage(payload[:payload_len],
		payload_type, payload_name)
}

//todo tengo pool
type TengoSandbox struct {
	ts           *tengo.Script
	tcancel       context.CancelFunc
	pack          *pipeline.PipelinePack
	injectMessage func(payload, payload_type, payload_name string) int
	config        map[string]interface{}
	field         int
	messageCopied bool
	globals       *pipeline.GlobalConfigStruct
	sbConfig      *sandbox.SandboxConfig
	lerr          error
}

// 初始化Tengo虚拟机
func CreateTengoSandbox(conf *sandbox.SandboxConfig) (sandbox.Sandbox, error) {
	//见 vm_test.go traceCompileRun
	return nil,nil
}

func (this *TengoSandbox) Init(dataFile string) error {
	//todo : load data file
	//return this.ts.DoFile(this.sbConfig.ScriptFilename)
	return nil
}

func (this *TengoSandbox) Stop() {
	//todo : save data file
	//todo : close tengo state
	//sandbox_stop(this.ts)
	
	this.tcancel()
}

func (this *TengoSandbox) Destroy(dataFile string) error {
	//todo : save data file
	//todo : close tengo state
	//todo : hook
	//this.ts.IsStackEmpty()
	//s := tengo.NewScript()

	//tengo_sethook(tengo, lstop, LUA_MASKCALL|LUA_MASKRET|LUA_MASKCOUNT, 1)
	return nil
}

/*
LSB_UNKNOWN     = 0,
LSB_RUNNING     = 1,
LSB_TERMINATED  = 2,
LSB_STOP        = 3
*/
func (this *TengoSandbox) Status() int {
	status := this.ts.Status(this.ts)
	switch status {
	case "running":
		return 1
	case "suspended":
		return 2
	case "dead":
		return 3
	case "normal":
		return 4
	}
	return 0
}

func (this *TengoSandbox) LastError() string {
	if this.lerr != nil {
		return this.lerr.Error()
	}
	return ""
}

func (this *TengoSandbox) Usage(utype, ustat int) uint {
	//todo
	return 10
	//return uint(lsb_usage(this.ts, lsb_usage_type(utype),
	//	lsb_usage_stat(ustat)))
}

//调用脚本里的函数
func (this *TengoSandbox) ProcessMessage(pack *pipeline.PipelinePack) int {
	return 0
}

func (this *TengoSandbox) TimerEvent(ns int64) int {

	return 0
}

//payload, payload_type, payload_name string
func (this *TengoSandbox) tengoInjectMessage(L *tengo.LState) int {
	payload := L.ToString(1)
	payload_type := L.ToString(2)
	payload_name := L.ToString(3)
	fmt.Println(payload, payload_type, payload_name)
	return 0
}

func (this *TengoSandbox)InjectMessage(f func(payload, payload_type, payload_name string) int)  {
	//f()
}