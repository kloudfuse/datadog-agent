// +build linux

// Code generated - DO NOT EDIT.

package probe

import (
	"reflect"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/security/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/eval"
)

// suppress unused package warning
var (
	_ *unsafe.Pointer
)

func (m *Model) GetIterator(field eval.Field) (eval.Iterator, error) {
	switch field {

	case "process.ancestors":
		return &model.ProcessAncestorsIterator{}, nil

	}

	return nil, &eval.ErrIteratorNotSupported{Field: field}
}

func (m *Model) GetEventTypes() []eval.EventType {
	return []eval.EventType{

		eval.EventType("capset"),

		eval.EventType("chmod"),

		eval.EventType("chown"),

		eval.EventType("exec"),

		eval.EventType("link"),

		eval.EventType("mkdir"),

		eval.EventType("open"),

		eval.EventType("removexattr"),

		eval.EventType("rename"),

		eval.EventType("rmdir"),

		eval.EventType("setgid"),

		eval.EventType("setuid"),

		eval.EventType("setxattr"),

		eval.EventType("unlink"),

		eval.EventType("utimes"),
	}
}

func (m *Model) GetEvaluator(field eval.Field, regID eval.RegisterID) (eval.Evaluator, error) {
	switch field {

	case "capset.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Capset.CapEffective)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "capset.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Capset.CapPermitted)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chmod.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Chmod.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chmod.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chmod.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chmod.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Chmod.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chmod.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chmod.File.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chmod.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Chmod.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chmod.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Chmod.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chmod.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chmod.File.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chmod.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chmod.File.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chmod.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chmod.File.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chmod.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Chmod.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chmod.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Chmod.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chmod.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chmod.File.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chmod.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Chmod.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chmod.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chmod.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chown.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Chown.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chown.file.destination.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chown.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chown.file.destination.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveChownGID(&(*Event)(ctx.Object).Chown)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chown.file.destination.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chown.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chown.file.destination.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveChownUID(&(*Event)(ctx.Object).Chown)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chown.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Chown.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chown.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chown.File.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chown.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Chown.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chown.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Chown.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chown.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chown.File.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chown.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chown.File.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chown.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chown.File.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chown.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Chown.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chown.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Chown.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chown.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chown.File.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "chown.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Chown.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "chown.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Chown.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveContainerID(&(*Event)(ctx.Object).ContainerContext)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveExecArgs(&(*Event)(ctx.Object).Exec)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).Exec.ArgsTruncated
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "exec.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsCapEffective(&(*Event)(ctx.Object).Exec.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsCapPermitted(&(*Event)(ctx.Object).Exec.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessComm(&(*Event)(ctx.Object).Exec.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.cookie":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveProcessCookie(&(*Event)(ctx.Object).Exec.Process))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsEGID(&(*Event)(ctx.Object).Exec.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsEGroup(&(*Event)(ctx.Object).Exec.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.envs":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveExecEnvs(&(*Event)(ctx.Object).Exec)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).Exec.EnvsTruncated
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "exec.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsEUID(&(*Event)(ctx.Object).Exec.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsEUser(&(*Event)(ctx.Object).Exec.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessContainerPath(&(*Event)(ctx.Object).Exec.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessFilesystem(&(*Event)(ctx.Object).Exec.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Exec.Process.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "exec.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Exec.Process.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Exec.Process.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "exec.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Exec.Process.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "exec.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Exec.Process.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "exec.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessBasename(&(*Event)(ctx.Object).Exec.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessInode(&(*Event)(ctx.Object).Exec.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Exec.Process.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "exec.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Exec.Process.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsFSGID(&(*Event)(ctx.Object).Exec.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsFSGroup(&(*Event)(ctx.Object).Exec.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsFSUID(&(*Event)(ctx.Object).Exec.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsFSUser(&(*Event)(ctx.Object).Exec.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsGID(&(*Event)(ctx.Object).Exec.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsGroup(&(*Event)(ctx.Object).Exec.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveProcessPPID(&(*Event)(ctx.Object).Exec.Process))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessTTY(&(*Event)(ctx.Object).Exec.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsUID(&(*Event)(ctx.Object).Exec.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "exec.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsUser(&(*Event)(ctx.Object).Exec.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Link.Source)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.destination.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Link.Target)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.destination.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Link.Target)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.destination.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Target.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.destination.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Link.Target.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.destination.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Link.Target)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.destination.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Target.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Target.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.destination.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Target.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.destination.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Link.Target)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.destination.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Link.Target)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.destination.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Target.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.destination.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Link.Target.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Link.Source)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Source.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Link.Source.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Link.Source)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Source.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Source.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Source.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Link.Source)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Link.Source)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.Source.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "link.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Link.Source.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "link.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Link.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "mkdir.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Mkdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "mkdir.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Mkdir.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "mkdir.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Mkdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "mkdir.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Mkdir.File.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "mkdir.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Mkdir.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "mkdir.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Mkdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "mkdir.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Mkdir.File.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "mkdir.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Mkdir.File.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "mkdir.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Mkdir.File.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "mkdir.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Mkdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "mkdir.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Mkdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "mkdir.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Mkdir.File.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "mkdir.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Mkdir.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "mkdir.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Mkdir.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "open.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Open.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "open.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Open.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "open.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Open.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "open.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Open.File.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "open.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Open.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "open.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Open.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "open.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Open.File.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "open.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Open.File.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "open.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Open.File.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "open.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Open.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "open.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Open.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "open.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Open.File.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "open.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Open.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "open.flags":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Open.Flags)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "open.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Open.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "process.ancestors.cap_effective":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveCredentialsCapEffective(&element.Credentials))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.cap_permitted":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveCredentialsCapPermitted(&element.Credentials))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.comm":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveProcessComm(&element.Process)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.cookie":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveProcessCookie(&element.Process))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.egid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveCredentialsEGID(&element.Credentials))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.egroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveCredentialsEGroup(&element.Credentials)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.euid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveCredentialsEUID(&element.Credentials))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.euser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveCredentialsEUser(&element.Credentials)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.container_path":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveProcessContainerPath(&element.Process)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.filesystem":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveProcessFilesystem(&element.Process)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int(element.ProcessContext.Process.FileFields.GID)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveGroup(&element.FileFields)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.inode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int(element.ProcessContext.Process.FileFields.Inode)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.mode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int(element.ProcessContext.Process.FileFields.Mode)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.mount_id":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int(element.ProcessContext.Process.FileFields.MountID)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.name":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveProcessBasename(&element.Process)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.path":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveProcessInode(&element.Process)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int(element.ProcessContext.Process.FileFields.UID)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.file.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveUser(&element.FileFields)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.fsgid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveCredentialsFSGID(&element.Credentials))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.fsgroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveCredentialsFSGroup(&element.Credentials)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.fsuid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveCredentialsFSUID(&element.Credentials))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.fsuser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveCredentialsFSUser(&element.Credentials)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveCredentialsGID(&element.Credentials))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveCredentialsGroup(&element.Credentials)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.id":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveContainerID(&element.ContainerContext)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.pid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int(element.ProcessContext.Pid)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.ppid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveProcessPPID(&element.Process))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.tid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int(element.ProcessContext.Tid)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.tty_name":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveProcessTTY(&element.Process)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result int

					element := (*model.ProcessCacheEntry)(value)

					result = int((*Event)(ctx.Object).ResolveCredentialsUID(&element.Credentials))

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.ancestors.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string

				iterator := &model.ProcessAncestorsIterator{}

				value := iterator.Front(ctx)
				for value != nil {
					var result string

					element := (*model.ProcessCacheEntry)(value)

					result = (*Event)(ctx.Object).ResolveCredentialsUser(&element.Credentials)

					results = append(results, result)

					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)

				return results
			}, Field: field,

			Weight: eval.IteratorWeight,
		}, nil

	case "process.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsCapEffective(&(*Event)(ctx.Object).ProcessContext.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsCapPermitted(&(*Event)(ctx.Object).ProcessContext.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessComm(&(*Event)(ctx.Object).ProcessContext.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.cookie":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveProcessCookie(&(*Event)(ctx.Object).ProcessContext.Process))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsEGID(&(*Event)(ctx.Object).ProcessContext.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsEGroup(&(*Event)(ctx.Object).ProcessContext.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsEUID(&(*Event)(ctx.Object).ProcessContext.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsEUser(&(*Event)(ctx.Object).ProcessContext.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessContainerPath(&(*Event)(ctx.Object).ProcessContext.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessFilesystem(&(*Event)(ctx.Object).ProcessContext.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ProcessContext.Process.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "process.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).ProcessContext.Process.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ProcessContext.Process.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "process.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ProcessContext.Process.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "process.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ProcessContext.Process.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "process.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessBasename(&(*Event)(ctx.Object).ProcessContext.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessInode(&(*Event)(ctx.Object).ProcessContext.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ProcessContext.Process.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "process.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).ProcessContext.Process.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsFSGID(&(*Event)(ctx.Object).ProcessContext.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsFSGroup(&(*Event)(ctx.Object).ProcessContext.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsFSUID(&(*Event)(ctx.Object).ProcessContext.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsFSUser(&(*Event)(ctx.Object).ProcessContext.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsGID(&(*Event)(ctx.Object).ProcessContext.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsGroup(&(*Event)(ctx.Object).ProcessContext.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ProcessContext.Pid)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "process.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveProcessPPID(&(*Event)(ctx.Object).ProcessContext.Process))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ProcessContext.Tid)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "process.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveProcessTTY(&(*Event)(ctx.Object).ProcessContext.Process)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).ResolveCredentialsUID(&(*Event)(ctx.Object).ProcessContext.Process.Credentials))
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "process.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveCredentialsUser(&(*Event)(ctx.Object).ProcessContext.Process.Credentials)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).RemoveXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.file.destination.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).GetXAttrName(&(*Event)(ctx.Object).RemoveXAttr)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.file.destination.namespace":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).GetXAttrNamespace(&(*Event)(ctx.Object).RemoveXAttr)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).RemoveXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).RemoveXAttr.File.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "removexattr.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).RemoveXAttr.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).RemoveXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).RemoveXAttr.File.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "removexattr.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).RemoveXAttr.File.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "removexattr.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).RemoveXAttr.File.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "removexattr.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).RemoveXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).RemoveXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).RemoveXAttr.File.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "removexattr.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).RemoveXAttr.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "removexattr.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).RemoveXAttr.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Rename.Old)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.destination.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Rename.New)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.destination.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Rename.New)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.destination.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.New.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.destination.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Rename.New.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.destination.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Rename.New)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.destination.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.New.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.New.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.destination.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.New.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.destination.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Rename.New)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.destination.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Rename.New)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.destination.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.New.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.destination.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Rename.New.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Rename.Old)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.Old.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Rename.Old.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Rename.Old)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.Old.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.Old.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.Old.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Rename.Old)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Rename.Old)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.Old.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rename.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Rename.Old.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rename.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rename.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rmdir.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Rmdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rmdir.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Rmdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rmdir.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rmdir.File.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rmdir.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Rmdir.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rmdir.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Rmdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rmdir.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rmdir.File.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rmdir.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rmdir.File.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rmdir.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rmdir.File.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rmdir.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Rmdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rmdir.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Rmdir.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rmdir.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rmdir.File.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "rmdir.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Rmdir.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "rmdir.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Rmdir.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setgid.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetGID.EGID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setgid.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveSetgidEGroup(&(*Event)(ctx.Object).SetGID)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setgid.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetGID.FSGID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setgid.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveSetgidFSGroup(&(*Event)(ctx.Object).SetGID)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setgid.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetGID.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setgid.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveSetgidGroup(&(*Event)(ctx.Object).SetGID)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setuid.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetUID.EUID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setuid.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveSetuidEUser(&(*Event)(ctx.Object).SetUID)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setuid.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetUID.FSUID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setuid.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveSetuidFSUser(&(*Event)(ctx.Object).SetUID)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setuid.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetUID.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setuid.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveSetuidUser(&(*Event)(ctx.Object).SetUID)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).SetXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.file.destination.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).GetXAttrName(&(*Event)(ctx.Object).SetXAttr)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.file.destination.namespace":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).GetXAttrNamespace(&(*Event)(ctx.Object).SetXAttr)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).SetXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetXAttr.File.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setxattr.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).SetXAttr.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).SetXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetXAttr.File.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setxattr.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetXAttr.File.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setxattr.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetXAttr.File.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setxattr.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).SetXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).SetXAttr.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetXAttr.File.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "setxattr.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).SetXAttr.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "setxattr.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).SetXAttr.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "unlink.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Unlink.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "unlink.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Unlink.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "unlink.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Unlink.File.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "unlink.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Unlink.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "unlink.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Unlink.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "unlink.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Unlink.File.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "unlink.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Unlink.File.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "unlink.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Unlink.File.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "unlink.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Unlink.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "unlink.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Unlink.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "unlink.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Unlink.File.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "unlink.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Unlink.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "unlink.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Unlink.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "utimes.file.container_path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileContainerPath(&(*Event)(ctx.Object).Utimes.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "utimes.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileFilesystem(&(*Event)(ctx.Object).Utimes.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "utimes.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Utimes.File.FileFields.GID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "utimes.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveGroup(&(*Event)(ctx.Object).Utimes.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "utimes.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {

				return (*Event)(ctx.Object).ResolveFileInUpperLayer(&(*Event)(ctx.Object).Utimes.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "utimes.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Utimes.File.FileFields.Inode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "utimes.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Utimes.File.FileFields.Mode)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "utimes.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Utimes.File.FileFields.MountID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "utimes.file.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileBasename(&(*Event)(ctx.Object).Utimes.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "utimes.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveFileInode(&(*Event)(ctx.Object).Utimes.File)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "utimes.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Utimes.File.FileFields.UID)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	case "utimes.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {

				return (*Event)(ctx.Object).ResolveUser(&(*Event)(ctx.Object).Utimes.File.FileFields)
			},
			Field: field,

			Weight: eval.HandlerWeight,
		}, nil

	case "utimes.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {

				return int((*Event)(ctx.Object).Utimes.SyscallEvent.Retval)
			},
			Field: field,

			Weight: eval.FunctionWeight,
		}, nil

	}

	return nil, &eval.ErrFieldNotFound{Field: field}
}

func (e *Event) GetFields() []eval.Field {
	return []eval.Field{

		"capset.cap_effective",

		"capset.cap_permitted",

		"chmod.file.container_path",

		"chmod.file.destination.mode",

		"chmod.file.filesystem",

		"chmod.file.gid",

		"chmod.file.group",

		"chmod.file.in_upper_layer",

		"chmod.file.inode",

		"chmod.file.mode",

		"chmod.file.mount_id",

		"chmod.file.name",

		"chmod.file.path",

		"chmod.file.uid",

		"chmod.file.user",

		"chmod.retval",

		"chown.file.container_path",

		"chown.file.destination.gid",

		"chown.file.destination.group",

		"chown.file.destination.uid",

		"chown.file.destination.user",

		"chown.file.filesystem",

		"chown.file.gid",

		"chown.file.group",

		"chown.file.in_upper_layer",

		"chown.file.inode",

		"chown.file.mode",

		"chown.file.mount_id",

		"chown.file.name",

		"chown.file.path",

		"chown.file.uid",

		"chown.file.user",

		"chown.retval",

		"container.id",

		"exec.args",

		"exec.args_truncated",

		"exec.cap_effective",

		"exec.cap_permitted",

		"exec.comm",

		"exec.cookie",

		"exec.egid",

		"exec.egroup",

		"exec.envs",

		"exec.envs_truncated",

		"exec.euid",

		"exec.euser",

		"exec.file.container_path",

		"exec.file.filesystem",

		"exec.file.gid",

		"exec.file.group",

		"exec.file.inode",

		"exec.file.mode",

		"exec.file.mount_id",

		"exec.file.name",

		"exec.file.path",

		"exec.file.uid",

		"exec.file.user",

		"exec.fsgid",

		"exec.fsgroup",

		"exec.fsuid",

		"exec.fsuser",

		"exec.gid",

		"exec.group",

		"exec.ppid",

		"exec.tty_name",

		"exec.uid",

		"exec.user",

		"link.file.container_path",

		"link.file.destination.container_path",

		"link.file.destination.filesystem",

		"link.file.destination.gid",

		"link.file.destination.group",

		"link.file.destination.in_upper_layer",

		"link.file.destination.inode",

		"link.file.destination.mode",

		"link.file.destination.mount_id",

		"link.file.destination.name",

		"link.file.destination.path",

		"link.file.destination.uid",

		"link.file.destination.user",

		"link.file.filesystem",

		"link.file.gid",

		"link.file.group",

		"link.file.in_upper_layer",

		"link.file.inode",

		"link.file.mode",

		"link.file.mount_id",

		"link.file.name",

		"link.file.path",

		"link.file.uid",

		"link.file.user",

		"link.retval",

		"mkdir.file.container_path",

		"mkdir.file.destination.mode",

		"mkdir.file.filesystem",

		"mkdir.file.gid",

		"mkdir.file.group",

		"mkdir.file.in_upper_layer",

		"mkdir.file.inode",

		"mkdir.file.mode",

		"mkdir.file.mount_id",

		"mkdir.file.name",

		"mkdir.file.path",

		"mkdir.file.uid",

		"mkdir.file.user",

		"mkdir.retval",

		"open.file.container_path",

		"open.file.destination.mode",

		"open.file.filesystem",

		"open.file.gid",

		"open.file.group",

		"open.file.in_upper_layer",

		"open.file.inode",

		"open.file.mode",

		"open.file.mount_id",

		"open.file.name",

		"open.file.path",

		"open.file.uid",

		"open.file.user",

		"open.flags",

		"open.retval",

		"process.ancestors.cap_effective",

		"process.ancestors.cap_permitted",

		"process.ancestors.comm",

		"process.ancestors.cookie",

		"process.ancestors.egid",

		"process.ancestors.egroup",

		"process.ancestors.euid",

		"process.ancestors.euser",

		"process.ancestors.file.container_path",

		"process.ancestors.file.filesystem",

		"process.ancestors.file.gid",

		"process.ancestors.file.group",

		"process.ancestors.file.inode",

		"process.ancestors.file.mode",

		"process.ancestors.file.mount_id",

		"process.ancestors.file.name",

		"process.ancestors.file.path",

		"process.ancestors.file.uid",

		"process.ancestors.file.user",

		"process.ancestors.fsgid",

		"process.ancestors.fsgroup",

		"process.ancestors.fsuid",

		"process.ancestors.fsuser",

		"process.ancestors.gid",

		"process.ancestors.group",

		"process.ancestors.id",

		"process.ancestors.pid",

		"process.ancestors.ppid",

		"process.ancestors.tid",

		"process.ancestors.tty_name",

		"process.ancestors.uid",

		"process.ancestors.user",

		"process.cap_effective",

		"process.cap_permitted",

		"process.comm",

		"process.cookie",

		"process.egid",

		"process.egroup",

		"process.euid",

		"process.euser",

		"process.file.container_path",

		"process.file.filesystem",

		"process.file.gid",

		"process.file.group",

		"process.file.inode",

		"process.file.mode",

		"process.file.mount_id",

		"process.file.name",

		"process.file.path",

		"process.file.uid",

		"process.file.user",

		"process.fsgid",

		"process.fsgroup",

		"process.fsuid",

		"process.fsuser",

		"process.gid",

		"process.group",

		"process.pid",

		"process.ppid",

		"process.tid",

		"process.tty_name",

		"process.uid",

		"process.user",

		"removexattr.file.container_path",

		"removexattr.file.destination.name",

		"removexattr.file.destination.namespace",

		"removexattr.file.filesystem",

		"removexattr.file.gid",

		"removexattr.file.group",

		"removexattr.file.in_upper_layer",

		"removexattr.file.inode",

		"removexattr.file.mode",

		"removexattr.file.mount_id",

		"removexattr.file.name",

		"removexattr.file.path",

		"removexattr.file.uid",

		"removexattr.file.user",

		"removexattr.retval",

		"rename.file.container_path",

		"rename.file.destination.container_path",

		"rename.file.destination.filesystem",

		"rename.file.destination.gid",

		"rename.file.destination.group",

		"rename.file.destination.in_upper_layer",

		"rename.file.destination.inode",

		"rename.file.destination.mode",

		"rename.file.destination.mount_id",

		"rename.file.destination.name",

		"rename.file.destination.path",

		"rename.file.destination.uid",

		"rename.file.destination.user",

		"rename.file.filesystem",

		"rename.file.gid",

		"rename.file.group",

		"rename.file.in_upper_layer",

		"rename.file.inode",

		"rename.file.mode",

		"rename.file.mount_id",

		"rename.file.name",

		"rename.file.path",

		"rename.file.uid",

		"rename.file.user",

		"rename.retval",

		"rmdir.file.container_path",

		"rmdir.file.filesystem",

		"rmdir.file.gid",

		"rmdir.file.group",

		"rmdir.file.in_upper_layer",

		"rmdir.file.inode",

		"rmdir.file.mode",

		"rmdir.file.mount_id",

		"rmdir.file.name",

		"rmdir.file.path",

		"rmdir.file.uid",

		"rmdir.file.user",

		"rmdir.retval",

		"setgid.egid",

		"setgid.egroup",

		"setgid.fsgid",

		"setgid.fsgroup",

		"setgid.gid",

		"setgid.group",

		"setuid.euid",

		"setuid.euser",

		"setuid.fsuid",

		"setuid.fsuser",

		"setuid.uid",

		"setuid.user",

		"setxattr.file.container_path",

		"setxattr.file.destination.name",

		"setxattr.file.destination.namespace",

		"setxattr.file.filesystem",

		"setxattr.file.gid",

		"setxattr.file.group",

		"setxattr.file.in_upper_layer",

		"setxattr.file.inode",

		"setxattr.file.mode",

		"setxattr.file.mount_id",

		"setxattr.file.name",

		"setxattr.file.path",

		"setxattr.file.uid",

		"setxattr.file.user",

		"setxattr.retval",

		"unlink.file.container_path",

		"unlink.file.filesystem",

		"unlink.file.gid",

		"unlink.file.group",

		"unlink.file.in_upper_layer",

		"unlink.file.inode",

		"unlink.file.mode",

		"unlink.file.mount_id",

		"unlink.file.name",

		"unlink.file.path",

		"unlink.file.uid",

		"unlink.file.user",

		"unlink.retval",

		"utimes.file.container_path",

		"utimes.file.filesystem",

		"utimes.file.gid",

		"utimes.file.group",

		"utimes.file.in_upper_layer",

		"utimes.file.inode",

		"utimes.file.mode",

		"utimes.file.mount_id",

		"utimes.file.name",

		"utimes.file.path",

		"utimes.file.uid",

		"utimes.file.user",

		"utimes.retval",
	}
}

func (e *Event) GetFieldValue(field eval.Field) (interface{}, error) {
	switch field {

	case "capset.cap_effective":

		return int(e.Capset.CapEffective), nil

	case "capset.cap_permitted":

		return int(e.Capset.CapPermitted), nil

	case "chmod.file.container_path":

		return e.ResolveFileContainerPath(&e.Chmod.File), nil

	case "chmod.file.destination.mode":

		return int(e.Chmod.Mode), nil

	case "chmod.file.filesystem":

		return e.ResolveFileFilesystem(&e.Chmod.File), nil

	case "chmod.file.gid":

		return int(e.Chmod.File.FileFields.GID), nil

	case "chmod.file.group":

		return e.ResolveGroup(&e.Chmod.File.FileFields), nil

	case "chmod.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Chmod.File), nil

	case "chmod.file.inode":

		return int(e.Chmod.File.FileFields.Inode), nil

	case "chmod.file.mode":

		return int(e.Chmod.File.FileFields.Mode), nil

	case "chmod.file.mount_id":

		return int(e.Chmod.File.FileFields.MountID), nil

	case "chmod.file.name":

		return e.ResolveFileBasename(&e.Chmod.File), nil

	case "chmod.file.path":

		return e.ResolveFileInode(&e.Chmod.File), nil

	case "chmod.file.uid":

		return int(e.Chmod.File.FileFields.UID), nil

	case "chmod.file.user":

		return e.ResolveUser(&e.Chmod.File.FileFields), nil

	case "chmod.retval":

		return int(e.Chmod.SyscallEvent.Retval), nil

	case "chown.file.container_path":

		return e.ResolveFileContainerPath(&e.Chown.File), nil

	case "chown.file.destination.gid":

		return int(e.Chown.GID), nil

	case "chown.file.destination.group":

		return e.ResolveChownGID(&e.Chown), nil

	case "chown.file.destination.uid":

		return int(e.Chown.UID), nil

	case "chown.file.destination.user":

		return e.ResolveChownUID(&e.Chown), nil

	case "chown.file.filesystem":

		return e.ResolveFileFilesystem(&e.Chown.File), nil

	case "chown.file.gid":

		return int(e.Chown.File.FileFields.GID), nil

	case "chown.file.group":

		return e.ResolveGroup(&e.Chown.File.FileFields), nil

	case "chown.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Chown.File), nil

	case "chown.file.inode":

		return int(e.Chown.File.FileFields.Inode), nil

	case "chown.file.mode":

		return int(e.Chown.File.FileFields.Mode), nil

	case "chown.file.mount_id":

		return int(e.Chown.File.FileFields.MountID), nil

	case "chown.file.name":

		return e.ResolveFileBasename(&e.Chown.File), nil

	case "chown.file.path":

		return e.ResolveFileInode(&e.Chown.File), nil

	case "chown.file.uid":

		return int(e.Chown.File.FileFields.UID), nil

	case "chown.file.user":

		return e.ResolveUser(&e.Chown.File.FileFields), nil

	case "chown.retval":

		return int(e.Chown.SyscallEvent.Retval), nil

	case "container.id":

		return e.ResolveContainerID(&e.ContainerContext), nil

	case "exec.args":

		return e.ResolveExecArgs(&e.Exec), nil

	case "exec.args_truncated":

		return e.Exec.ArgsTruncated, nil

	case "exec.cap_effective":

		return int(e.ResolveCredentialsCapEffective(&e.Exec.Process.Credentials)), nil

	case "exec.cap_permitted":

		return int(e.ResolveCredentialsCapPermitted(&e.Exec.Process.Credentials)), nil

	case "exec.comm":

		return e.ResolveProcessComm(&e.Exec.Process), nil

	case "exec.cookie":

		return int(e.ResolveProcessCookie(&e.Exec.Process)), nil

	case "exec.egid":

		return int(e.ResolveCredentialsEGID(&e.Exec.Process.Credentials)), nil

	case "exec.egroup":

		return e.ResolveCredentialsEGroup(&e.Exec.Process.Credentials), nil

	case "exec.envs":

		return e.ResolveExecEnvs(&e.Exec), nil

	case "exec.envs_truncated":

		return e.Exec.EnvsTruncated, nil

	case "exec.euid":

		return int(e.ResolveCredentialsEUID(&e.Exec.Process.Credentials)), nil

	case "exec.euser":

		return e.ResolveCredentialsEUser(&e.Exec.Process.Credentials), nil

	case "exec.file.container_path":

		return e.ResolveProcessContainerPath(&e.Exec.Process), nil

	case "exec.file.filesystem":

		return e.ResolveProcessFilesystem(&e.Exec.Process), nil

	case "exec.file.gid":

		return int(e.Exec.Process.FileFields.GID), nil

	case "exec.file.group":

		return e.ResolveGroup(&e.Exec.Process.FileFields), nil

	case "exec.file.inode":

		return int(e.Exec.Process.FileFields.Inode), nil

	case "exec.file.mode":

		return int(e.Exec.Process.FileFields.Mode), nil

	case "exec.file.mount_id":

		return int(e.Exec.Process.FileFields.MountID), nil

	case "exec.file.name":

		return e.ResolveProcessBasename(&e.Exec.Process), nil

	case "exec.file.path":

		return e.ResolveProcessInode(&e.Exec.Process), nil

	case "exec.file.uid":

		return int(e.Exec.Process.FileFields.UID), nil

	case "exec.file.user":

		return e.ResolveUser(&e.Exec.Process.FileFields), nil

	case "exec.fsgid":

		return int(e.ResolveCredentialsFSGID(&e.Exec.Process.Credentials)), nil

	case "exec.fsgroup":

		return e.ResolveCredentialsFSGroup(&e.Exec.Process.Credentials), nil

	case "exec.fsuid":

		return int(e.ResolveCredentialsFSUID(&e.Exec.Process.Credentials)), nil

	case "exec.fsuser":

		return e.ResolveCredentialsFSUser(&e.Exec.Process.Credentials), nil

	case "exec.gid":

		return int(e.ResolveCredentialsGID(&e.Exec.Process.Credentials)), nil

	case "exec.group":

		return e.ResolveCredentialsGroup(&e.Exec.Process.Credentials), nil

	case "exec.ppid":

		return int(e.ResolveProcessPPID(&e.Exec.Process)), nil

	case "exec.tty_name":

		return e.ResolveProcessTTY(&e.Exec.Process), nil

	case "exec.uid":

		return int(e.ResolveCredentialsUID(&e.Exec.Process.Credentials)), nil

	case "exec.user":

		return e.ResolveCredentialsUser(&e.Exec.Process.Credentials), nil

	case "link.file.container_path":

		return e.ResolveFileContainerPath(&e.Link.Source), nil

	case "link.file.destination.container_path":

		return e.ResolveFileContainerPath(&e.Link.Target), nil

	case "link.file.destination.filesystem":

		return e.ResolveFileFilesystem(&e.Link.Target), nil

	case "link.file.destination.gid":

		return int(e.Link.Target.FileFields.GID), nil

	case "link.file.destination.group":

		return e.ResolveGroup(&e.Link.Target.FileFields), nil

	case "link.file.destination.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Link.Target), nil

	case "link.file.destination.inode":

		return int(e.Link.Target.FileFields.Inode), nil

	case "link.file.destination.mode":

		return int(e.Link.Target.FileFields.Mode), nil

	case "link.file.destination.mount_id":

		return int(e.Link.Target.FileFields.MountID), nil

	case "link.file.destination.name":

		return e.ResolveFileBasename(&e.Link.Target), nil

	case "link.file.destination.path":

		return e.ResolveFileInode(&e.Link.Target), nil

	case "link.file.destination.uid":

		return int(e.Link.Target.FileFields.UID), nil

	case "link.file.destination.user":

		return e.ResolveUser(&e.Link.Target.FileFields), nil

	case "link.file.filesystem":

		return e.ResolveFileFilesystem(&e.Link.Source), nil

	case "link.file.gid":

		return int(e.Link.Source.FileFields.GID), nil

	case "link.file.group":

		return e.ResolveGroup(&e.Link.Source.FileFields), nil

	case "link.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Link.Source), nil

	case "link.file.inode":

		return int(e.Link.Source.FileFields.Inode), nil

	case "link.file.mode":

		return int(e.Link.Source.FileFields.Mode), nil

	case "link.file.mount_id":

		return int(e.Link.Source.FileFields.MountID), nil

	case "link.file.name":

		return e.ResolveFileBasename(&e.Link.Source), nil

	case "link.file.path":

		return e.ResolveFileInode(&e.Link.Source), nil

	case "link.file.uid":

		return int(e.Link.Source.FileFields.UID), nil

	case "link.file.user":

		return e.ResolveUser(&e.Link.Source.FileFields), nil

	case "link.retval":

		return int(e.Link.SyscallEvent.Retval), nil

	case "mkdir.file.container_path":

		return e.ResolveFileContainerPath(&e.Mkdir.File), nil

	case "mkdir.file.destination.mode":

		return int(e.Mkdir.Mode), nil

	case "mkdir.file.filesystem":

		return e.ResolveFileFilesystem(&e.Mkdir.File), nil

	case "mkdir.file.gid":

		return int(e.Mkdir.File.FileFields.GID), nil

	case "mkdir.file.group":

		return e.ResolveGroup(&e.Mkdir.File.FileFields), nil

	case "mkdir.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Mkdir.File), nil

	case "mkdir.file.inode":

		return int(e.Mkdir.File.FileFields.Inode), nil

	case "mkdir.file.mode":

		return int(e.Mkdir.File.FileFields.Mode), nil

	case "mkdir.file.mount_id":

		return int(e.Mkdir.File.FileFields.MountID), nil

	case "mkdir.file.name":

		return e.ResolveFileBasename(&e.Mkdir.File), nil

	case "mkdir.file.path":

		return e.ResolveFileInode(&e.Mkdir.File), nil

	case "mkdir.file.uid":

		return int(e.Mkdir.File.FileFields.UID), nil

	case "mkdir.file.user":

		return e.ResolveUser(&e.Mkdir.File.FileFields), nil

	case "mkdir.retval":

		return int(e.Mkdir.SyscallEvent.Retval), nil

	case "open.file.container_path":

		return e.ResolveFileContainerPath(&e.Open.File), nil

	case "open.file.destination.mode":

		return int(e.Open.Mode), nil

	case "open.file.filesystem":

		return e.ResolveFileFilesystem(&e.Open.File), nil

	case "open.file.gid":

		return int(e.Open.File.FileFields.GID), nil

	case "open.file.group":

		return e.ResolveGroup(&e.Open.File.FileFields), nil

	case "open.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Open.File), nil

	case "open.file.inode":

		return int(e.Open.File.FileFields.Inode), nil

	case "open.file.mode":

		return int(e.Open.File.FileFields.Mode), nil

	case "open.file.mount_id":

		return int(e.Open.File.FileFields.MountID), nil

	case "open.file.name":

		return e.ResolveFileBasename(&e.Open.File), nil

	case "open.file.path":

		return e.ResolveFileInode(&e.Open.File), nil

	case "open.file.uid":

		return int(e.Open.File.FileFields.UID), nil

	case "open.file.user":

		return e.ResolveUser(&e.Open.File.FileFields), nil

	case "open.flags":

		return int(e.Open.Flags), nil

	case "open.retval":

		return int(e.Open.SyscallEvent.Retval), nil

	case "process.ancestors.cap_effective":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveCredentialsCapEffective(&element.Credentials))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.cap_permitted":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveCredentialsCapPermitted(&element.Credentials))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.comm":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveProcessComm(&element.Process)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.cookie":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveProcessCookie(&element.Process))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.egid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveCredentialsEGID(&element.Credentials))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.egroup":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveCredentialsEGroup(&element.Credentials)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.euid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveCredentialsEUID(&element.Credentials))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.euser":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveCredentialsEUser(&element.Credentials)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.container_path":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveProcessContainerPath(&element.Process)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.filesystem":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveProcessFilesystem(&element.Process)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.gid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int(element.ProcessContext.Process.FileFields.GID)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.group":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveGroup(&element.FileFields)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.inode":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int(element.ProcessContext.Process.FileFields.Inode)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.mode":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int(element.ProcessContext.Process.FileFields.Mode)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.mount_id":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int(element.ProcessContext.Process.FileFields.MountID)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.name":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveProcessBasename(&element.Process)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.path":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveProcessInode(&element.Process)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.uid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int(element.ProcessContext.Process.FileFields.UID)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.file.user":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveUser(&element.FileFields)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.fsgid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveCredentialsFSGID(&element.Credentials))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.fsgroup":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveCredentialsFSGroup(&element.Credentials)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.fsuid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveCredentialsFSUID(&element.Credentials))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.fsuser":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveCredentialsFSUser(&element.Credentials)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.gid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveCredentialsGID(&element.Credentials))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.group":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveCredentialsGroup(&element.Credentials)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.id":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveContainerID(&element.ContainerContext)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.pid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int(element.ProcessContext.Pid)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.ppid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveProcessPPID(&element.Process))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.tid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int(element.ProcessContext.Tid)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.tty_name":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveProcessTTY(&element.Process)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.uid":

		var values []int

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := int((*Event)(ctx.Object).ResolveCredentialsUID(&element.Credentials))

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.ancestors.user":

		var values []string

		ctx := eval.NewContext(unsafe.Pointer(e))

		iterator := &model.ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)

		for ptr != nil {

			element := (*model.ProcessCacheEntry)(ptr)

			result := (*Event)(ctx.Object).ResolveCredentialsUser(&element.Credentials)

			values = append(values, result)

			ptr = iterator.Next()
		}

		return values, nil

	case "process.cap_effective":

		return int(e.ResolveCredentialsCapEffective(&e.ProcessContext.Process.Credentials)), nil

	case "process.cap_permitted":

		return int(e.ResolveCredentialsCapPermitted(&e.ProcessContext.Process.Credentials)), nil

	case "process.comm":

		return e.ResolveProcessComm(&e.ProcessContext.Process), nil

	case "process.cookie":

		return int(e.ResolveProcessCookie(&e.ProcessContext.Process)), nil

	case "process.egid":

		return int(e.ResolveCredentialsEGID(&e.ProcessContext.Process.Credentials)), nil

	case "process.egroup":

		return e.ResolveCredentialsEGroup(&e.ProcessContext.Process.Credentials), nil

	case "process.euid":

		return int(e.ResolveCredentialsEUID(&e.ProcessContext.Process.Credentials)), nil

	case "process.euser":

		return e.ResolveCredentialsEUser(&e.ProcessContext.Process.Credentials), nil

	case "process.file.container_path":

		return e.ResolveProcessContainerPath(&e.ProcessContext.Process), nil

	case "process.file.filesystem":

		return e.ResolveProcessFilesystem(&e.ProcessContext.Process), nil

	case "process.file.gid":

		return int(e.ProcessContext.Process.FileFields.GID), nil

	case "process.file.group":

		return e.ResolveGroup(&e.ProcessContext.Process.FileFields), nil

	case "process.file.inode":

		return int(e.ProcessContext.Process.FileFields.Inode), nil

	case "process.file.mode":

		return int(e.ProcessContext.Process.FileFields.Mode), nil

	case "process.file.mount_id":

		return int(e.ProcessContext.Process.FileFields.MountID), nil

	case "process.file.name":

		return e.ResolveProcessBasename(&e.ProcessContext.Process), nil

	case "process.file.path":

		return e.ResolveProcessInode(&e.ProcessContext.Process), nil

	case "process.file.uid":

		return int(e.ProcessContext.Process.FileFields.UID), nil

	case "process.file.user":

		return e.ResolveUser(&e.ProcessContext.Process.FileFields), nil

	case "process.fsgid":

		return int(e.ResolveCredentialsFSGID(&e.ProcessContext.Process.Credentials)), nil

	case "process.fsgroup":

		return e.ResolveCredentialsFSGroup(&e.ProcessContext.Process.Credentials), nil

	case "process.fsuid":

		return int(e.ResolveCredentialsFSUID(&e.ProcessContext.Process.Credentials)), nil

	case "process.fsuser":

		return e.ResolveCredentialsFSUser(&e.ProcessContext.Process.Credentials), nil

	case "process.gid":

		return int(e.ResolveCredentialsGID(&e.ProcessContext.Process.Credentials)), nil

	case "process.group":

		return e.ResolveCredentialsGroup(&e.ProcessContext.Process.Credentials), nil

	case "process.pid":

		return int(e.ProcessContext.Pid), nil

	case "process.ppid":

		return int(e.ResolveProcessPPID(&e.ProcessContext.Process)), nil

	case "process.tid":

		return int(e.ProcessContext.Tid), nil

	case "process.tty_name":

		return e.ResolveProcessTTY(&e.ProcessContext.Process), nil

	case "process.uid":

		return int(e.ResolveCredentialsUID(&e.ProcessContext.Process.Credentials)), nil

	case "process.user":

		return e.ResolveCredentialsUser(&e.ProcessContext.Process.Credentials), nil

	case "removexattr.file.container_path":

		return e.ResolveFileContainerPath(&e.RemoveXAttr.File), nil

	case "removexattr.file.destination.name":

		return e.GetXAttrName(&e.RemoveXAttr), nil

	case "removexattr.file.destination.namespace":

		return e.GetXAttrNamespace(&e.RemoveXAttr), nil

	case "removexattr.file.filesystem":

		return e.ResolveFileFilesystem(&e.RemoveXAttr.File), nil

	case "removexattr.file.gid":

		return int(e.RemoveXAttr.File.FileFields.GID), nil

	case "removexattr.file.group":

		return e.ResolveGroup(&e.RemoveXAttr.File.FileFields), nil

	case "removexattr.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.RemoveXAttr.File), nil

	case "removexattr.file.inode":

		return int(e.RemoveXAttr.File.FileFields.Inode), nil

	case "removexattr.file.mode":

		return int(e.RemoveXAttr.File.FileFields.Mode), nil

	case "removexattr.file.mount_id":

		return int(e.RemoveXAttr.File.FileFields.MountID), nil

	case "removexattr.file.name":

		return e.ResolveFileBasename(&e.RemoveXAttr.File), nil

	case "removexattr.file.path":

		return e.ResolveFileInode(&e.RemoveXAttr.File), nil

	case "removexattr.file.uid":

		return int(e.RemoveXAttr.File.FileFields.UID), nil

	case "removexattr.file.user":

		return e.ResolveUser(&e.RemoveXAttr.File.FileFields), nil

	case "removexattr.retval":

		return int(e.RemoveXAttr.SyscallEvent.Retval), nil

	case "rename.file.container_path":

		return e.ResolveFileContainerPath(&e.Rename.Old), nil

	case "rename.file.destination.container_path":

		return e.ResolveFileContainerPath(&e.Rename.New), nil

	case "rename.file.destination.filesystem":

		return e.ResolveFileFilesystem(&e.Rename.New), nil

	case "rename.file.destination.gid":

		return int(e.Rename.New.FileFields.GID), nil

	case "rename.file.destination.group":

		return e.ResolveGroup(&e.Rename.New.FileFields), nil

	case "rename.file.destination.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Rename.New), nil

	case "rename.file.destination.inode":

		return int(e.Rename.New.FileFields.Inode), nil

	case "rename.file.destination.mode":

		return int(e.Rename.New.FileFields.Mode), nil

	case "rename.file.destination.mount_id":

		return int(e.Rename.New.FileFields.MountID), nil

	case "rename.file.destination.name":

		return e.ResolveFileBasename(&e.Rename.New), nil

	case "rename.file.destination.path":

		return e.ResolveFileInode(&e.Rename.New), nil

	case "rename.file.destination.uid":

		return int(e.Rename.New.FileFields.UID), nil

	case "rename.file.destination.user":

		return e.ResolveUser(&e.Rename.New.FileFields), nil

	case "rename.file.filesystem":

		return e.ResolveFileFilesystem(&e.Rename.Old), nil

	case "rename.file.gid":

		return int(e.Rename.Old.FileFields.GID), nil

	case "rename.file.group":

		return e.ResolveGroup(&e.Rename.Old.FileFields), nil

	case "rename.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Rename.Old), nil

	case "rename.file.inode":

		return int(e.Rename.Old.FileFields.Inode), nil

	case "rename.file.mode":

		return int(e.Rename.Old.FileFields.Mode), nil

	case "rename.file.mount_id":

		return int(e.Rename.Old.FileFields.MountID), nil

	case "rename.file.name":

		return e.ResolveFileBasename(&e.Rename.Old), nil

	case "rename.file.path":

		return e.ResolveFileInode(&e.Rename.Old), nil

	case "rename.file.uid":

		return int(e.Rename.Old.FileFields.UID), nil

	case "rename.file.user":

		return e.ResolveUser(&e.Rename.Old.FileFields), nil

	case "rename.retval":

		return int(e.Rename.SyscallEvent.Retval), nil

	case "rmdir.file.container_path":

		return e.ResolveFileContainerPath(&e.Rmdir.File), nil

	case "rmdir.file.filesystem":

		return e.ResolveFileFilesystem(&e.Rmdir.File), nil

	case "rmdir.file.gid":

		return int(e.Rmdir.File.FileFields.GID), nil

	case "rmdir.file.group":

		return e.ResolveGroup(&e.Rmdir.File.FileFields), nil

	case "rmdir.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Rmdir.File), nil

	case "rmdir.file.inode":

		return int(e.Rmdir.File.FileFields.Inode), nil

	case "rmdir.file.mode":

		return int(e.Rmdir.File.FileFields.Mode), nil

	case "rmdir.file.mount_id":

		return int(e.Rmdir.File.FileFields.MountID), nil

	case "rmdir.file.name":

		return e.ResolveFileBasename(&e.Rmdir.File), nil

	case "rmdir.file.path":

		return e.ResolveFileInode(&e.Rmdir.File), nil

	case "rmdir.file.uid":

		return int(e.Rmdir.File.FileFields.UID), nil

	case "rmdir.file.user":

		return e.ResolveUser(&e.Rmdir.File.FileFields), nil

	case "rmdir.retval":

		return int(e.Rmdir.SyscallEvent.Retval), nil

	case "setgid.egid":

		return int(e.SetGID.EGID), nil

	case "setgid.egroup":

		return e.ResolveSetgidEGroup(&e.SetGID), nil

	case "setgid.fsgid":

		return int(e.SetGID.FSGID), nil

	case "setgid.fsgroup":

		return e.ResolveSetgidFSGroup(&e.SetGID), nil

	case "setgid.gid":

		return int(e.SetGID.GID), nil

	case "setgid.group":

		return e.ResolveSetgidGroup(&e.SetGID), nil

	case "setuid.euid":

		return int(e.SetUID.EUID), nil

	case "setuid.euser":

		return e.ResolveSetuidEUser(&e.SetUID), nil

	case "setuid.fsuid":

		return int(e.SetUID.FSUID), nil

	case "setuid.fsuser":

		return e.ResolveSetuidFSUser(&e.SetUID), nil

	case "setuid.uid":

		return int(e.SetUID.UID), nil

	case "setuid.user":

		return e.ResolveSetuidUser(&e.SetUID), nil

	case "setxattr.file.container_path":

		return e.ResolveFileContainerPath(&e.SetXAttr.File), nil

	case "setxattr.file.destination.name":

		return e.GetXAttrName(&e.SetXAttr), nil

	case "setxattr.file.destination.namespace":

		return e.GetXAttrNamespace(&e.SetXAttr), nil

	case "setxattr.file.filesystem":

		return e.ResolveFileFilesystem(&e.SetXAttr.File), nil

	case "setxattr.file.gid":

		return int(e.SetXAttr.File.FileFields.GID), nil

	case "setxattr.file.group":

		return e.ResolveGroup(&e.SetXAttr.File.FileFields), nil

	case "setxattr.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.SetXAttr.File), nil

	case "setxattr.file.inode":

		return int(e.SetXAttr.File.FileFields.Inode), nil

	case "setxattr.file.mode":

		return int(e.SetXAttr.File.FileFields.Mode), nil

	case "setxattr.file.mount_id":

		return int(e.SetXAttr.File.FileFields.MountID), nil

	case "setxattr.file.name":

		return e.ResolveFileBasename(&e.SetXAttr.File), nil

	case "setxattr.file.path":

		return e.ResolveFileInode(&e.SetXAttr.File), nil

	case "setxattr.file.uid":

		return int(e.SetXAttr.File.FileFields.UID), nil

	case "setxattr.file.user":

		return e.ResolveUser(&e.SetXAttr.File.FileFields), nil

	case "setxattr.retval":

		return int(e.SetXAttr.SyscallEvent.Retval), nil

	case "unlink.file.container_path":

		return e.ResolveFileContainerPath(&e.Unlink.File), nil

	case "unlink.file.filesystem":

		return e.ResolveFileFilesystem(&e.Unlink.File), nil

	case "unlink.file.gid":

		return int(e.Unlink.File.FileFields.GID), nil

	case "unlink.file.group":

		return e.ResolveGroup(&e.Unlink.File.FileFields), nil

	case "unlink.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Unlink.File), nil

	case "unlink.file.inode":

		return int(e.Unlink.File.FileFields.Inode), nil

	case "unlink.file.mode":

		return int(e.Unlink.File.FileFields.Mode), nil

	case "unlink.file.mount_id":

		return int(e.Unlink.File.FileFields.MountID), nil

	case "unlink.file.name":

		return e.ResolveFileBasename(&e.Unlink.File), nil

	case "unlink.file.path":

		return e.ResolveFileInode(&e.Unlink.File), nil

	case "unlink.file.uid":

		return int(e.Unlink.File.FileFields.UID), nil

	case "unlink.file.user":

		return e.ResolveUser(&e.Unlink.File.FileFields), nil

	case "unlink.retval":

		return int(e.Unlink.SyscallEvent.Retval), nil

	case "utimes.file.container_path":

		return e.ResolveFileContainerPath(&e.Utimes.File), nil

	case "utimes.file.filesystem":

		return e.ResolveFileFilesystem(&e.Utimes.File), nil

	case "utimes.file.gid":

		return int(e.Utimes.File.FileFields.GID), nil

	case "utimes.file.group":

		return e.ResolveGroup(&e.Utimes.File.FileFields), nil

	case "utimes.file.in_upper_layer":

		return e.ResolveFileInUpperLayer(&e.Utimes.File), nil

	case "utimes.file.inode":

		return int(e.Utimes.File.FileFields.Inode), nil

	case "utimes.file.mode":

		return int(e.Utimes.File.FileFields.Mode), nil

	case "utimes.file.mount_id":

		return int(e.Utimes.File.FileFields.MountID), nil

	case "utimes.file.name":

		return e.ResolveFileBasename(&e.Utimes.File), nil

	case "utimes.file.path":

		return e.ResolveFileInode(&e.Utimes.File), nil

	case "utimes.file.uid":

		return int(e.Utimes.File.FileFields.UID), nil

	case "utimes.file.user":

		return e.ResolveUser(&e.Utimes.File.FileFields), nil

	case "utimes.retval":

		return int(e.Utimes.SyscallEvent.Retval), nil

	}

	return nil, &eval.ErrFieldNotFound{Field: field}
}

func (e *Event) GetFieldEventType(field eval.Field) (eval.EventType, error) {
	switch field {

	case "capset.cap_effective":
		return "capset", nil

	case "capset.cap_permitted":
		return "capset", nil

	case "chmod.file.container_path":
		return "chmod", nil

	case "chmod.file.destination.mode":
		return "chmod", nil

	case "chmod.file.filesystem":
		return "chmod", nil

	case "chmod.file.gid":
		return "chmod", nil

	case "chmod.file.group":
		return "chmod", nil

	case "chmod.file.in_upper_layer":
		return "chmod", nil

	case "chmod.file.inode":
		return "chmod", nil

	case "chmod.file.mode":
		return "chmod", nil

	case "chmod.file.mount_id":
		return "chmod", nil

	case "chmod.file.name":
		return "chmod", nil

	case "chmod.file.path":
		return "chmod", nil

	case "chmod.file.uid":
		return "chmod", nil

	case "chmod.file.user":
		return "chmod", nil

	case "chmod.retval":
		return "chmod", nil

	case "chown.file.container_path":
		return "chown", nil

	case "chown.file.destination.gid":
		return "chown", nil

	case "chown.file.destination.group":
		return "chown", nil

	case "chown.file.destination.uid":
		return "chown", nil

	case "chown.file.destination.user":
		return "chown", nil

	case "chown.file.filesystem":
		return "chown", nil

	case "chown.file.gid":
		return "chown", nil

	case "chown.file.group":
		return "chown", nil

	case "chown.file.in_upper_layer":
		return "chown", nil

	case "chown.file.inode":
		return "chown", nil

	case "chown.file.mode":
		return "chown", nil

	case "chown.file.mount_id":
		return "chown", nil

	case "chown.file.name":
		return "chown", nil

	case "chown.file.path":
		return "chown", nil

	case "chown.file.uid":
		return "chown", nil

	case "chown.file.user":
		return "chown", nil

	case "chown.retval":
		return "chown", nil

	case "container.id":
		return "*", nil

	case "exec.args":
		return "exec", nil

	case "exec.args_truncated":
		return "exec", nil

	case "exec.cap_effective":
		return "exec", nil

	case "exec.cap_permitted":
		return "exec", nil

	case "exec.comm":
		return "exec", nil

	case "exec.cookie":
		return "exec", nil

	case "exec.egid":
		return "exec", nil

	case "exec.egroup":
		return "exec", nil

	case "exec.envs":
		return "exec", nil

	case "exec.envs_truncated":
		return "exec", nil

	case "exec.euid":
		return "exec", nil

	case "exec.euser":
		return "exec", nil

	case "exec.file.container_path":
		return "exec", nil

	case "exec.file.filesystem":
		return "exec", nil

	case "exec.file.gid":
		return "exec", nil

	case "exec.file.group":
		return "exec", nil

	case "exec.file.inode":
		return "exec", nil

	case "exec.file.mode":
		return "exec", nil

	case "exec.file.mount_id":
		return "exec", nil

	case "exec.file.name":
		return "exec", nil

	case "exec.file.path":
		return "exec", nil

	case "exec.file.uid":
		return "exec", nil

	case "exec.file.user":
		return "exec", nil

	case "exec.fsgid":
		return "exec", nil

	case "exec.fsgroup":
		return "exec", nil

	case "exec.fsuid":
		return "exec", nil

	case "exec.fsuser":
		return "exec", nil

	case "exec.gid":
		return "exec", nil

	case "exec.group":
		return "exec", nil

	case "exec.ppid":
		return "exec", nil

	case "exec.tty_name":
		return "exec", nil

	case "exec.uid":
		return "exec", nil

	case "exec.user":
		return "exec", nil

	case "link.file.container_path":
		return "link", nil

	case "link.file.destination.container_path":
		return "link", nil

	case "link.file.destination.filesystem":
		return "link", nil

	case "link.file.destination.gid":
		return "link", nil

	case "link.file.destination.group":
		return "link", nil

	case "link.file.destination.in_upper_layer":
		return "link", nil

	case "link.file.destination.inode":
		return "link", nil

	case "link.file.destination.mode":
		return "link", nil

	case "link.file.destination.mount_id":
		return "link", nil

	case "link.file.destination.name":
		return "link", nil

	case "link.file.destination.path":
		return "link", nil

	case "link.file.destination.uid":
		return "link", nil

	case "link.file.destination.user":
		return "link", nil

	case "link.file.filesystem":
		return "link", nil

	case "link.file.gid":
		return "link", nil

	case "link.file.group":
		return "link", nil

	case "link.file.in_upper_layer":
		return "link", nil

	case "link.file.inode":
		return "link", nil

	case "link.file.mode":
		return "link", nil

	case "link.file.mount_id":
		return "link", nil

	case "link.file.name":
		return "link", nil

	case "link.file.path":
		return "link", nil

	case "link.file.uid":
		return "link", nil

	case "link.file.user":
		return "link", nil

	case "link.retval":
		return "link", nil

	case "mkdir.file.container_path":
		return "mkdir", nil

	case "mkdir.file.destination.mode":
		return "mkdir", nil

	case "mkdir.file.filesystem":
		return "mkdir", nil

	case "mkdir.file.gid":
		return "mkdir", nil

	case "mkdir.file.group":
		return "mkdir", nil

	case "mkdir.file.in_upper_layer":
		return "mkdir", nil

	case "mkdir.file.inode":
		return "mkdir", nil

	case "mkdir.file.mode":
		return "mkdir", nil

	case "mkdir.file.mount_id":
		return "mkdir", nil

	case "mkdir.file.name":
		return "mkdir", nil

	case "mkdir.file.path":
		return "mkdir", nil

	case "mkdir.file.uid":
		return "mkdir", nil

	case "mkdir.file.user":
		return "mkdir", nil

	case "mkdir.retval":
		return "mkdir", nil

	case "open.file.container_path":
		return "open", nil

	case "open.file.destination.mode":
		return "open", nil

	case "open.file.filesystem":
		return "open", nil

	case "open.file.gid":
		return "open", nil

	case "open.file.group":
		return "open", nil

	case "open.file.in_upper_layer":
		return "open", nil

	case "open.file.inode":
		return "open", nil

	case "open.file.mode":
		return "open", nil

	case "open.file.mount_id":
		return "open", nil

	case "open.file.name":
		return "open", nil

	case "open.file.path":
		return "open", nil

	case "open.file.uid":
		return "open", nil

	case "open.file.user":
		return "open", nil

	case "open.flags":
		return "open", nil

	case "open.retval":
		return "open", nil

	case "process.ancestors.cap_effective":
		return "*", nil

	case "process.ancestors.cap_permitted":
		return "*", nil

	case "process.ancestors.comm":
		return "*", nil

	case "process.ancestors.cookie":
		return "*", nil

	case "process.ancestors.egid":
		return "*", nil

	case "process.ancestors.egroup":
		return "*", nil

	case "process.ancestors.euid":
		return "*", nil

	case "process.ancestors.euser":
		return "*", nil

	case "process.ancestors.file.container_path":
		return "*", nil

	case "process.ancestors.file.filesystem":
		return "*", nil

	case "process.ancestors.file.gid":
		return "*", nil

	case "process.ancestors.file.group":
		return "*", nil

	case "process.ancestors.file.inode":
		return "*", nil

	case "process.ancestors.file.mode":
		return "*", nil

	case "process.ancestors.file.mount_id":
		return "*", nil

	case "process.ancestors.file.name":
		return "*", nil

	case "process.ancestors.file.path":
		return "*", nil

	case "process.ancestors.file.uid":
		return "*", nil

	case "process.ancestors.file.user":
		return "*", nil

	case "process.ancestors.fsgid":
		return "*", nil

	case "process.ancestors.fsgroup":
		return "*", nil

	case "process.ancestors.fsuid":
		return "*", nil

	case "process.ancestors.fsuser":
		return "*", nil

	case "process.ancestors.gid":
		return "*", nil

	case "process.ancestors.group":
		return "*", nil

	case "process.ancestors.id":
		return "*", nil

	case "process.ancestors.pid":
		return "*", nil

	case "process.ancestors.ppid":
		return "*", nil

	case "process.ancestors.tid":
		return "*", nil

	case "process.ancestors.tty_name":
		return "*", nil

	case "process.ancestors.uid":
		return "*", nil

	case "process.ancestors.user":
		return "*", nil

	case "process.cap_effective":
		return "*", nil

	case "process.cap_permitted":
		return "*", nil

	case "process.comm":
		return "*", nil

	case "process.cookie":
		return "*", nil

	case "process.egid":
		return "*", nil

	case "process.egroup":
		return "*", nil

	case "process.euid":
		return "*", nil

	case "process.euser":
		return "*", nil

	case "process.file.container_path":
		return "*", nil

	case "process.file.filesystem":
		return "*", nil

	case "process.file.gid":
		return "*", nil

	case "process.file.group":
		return "*", nil

	case "process.file.inode":
		return "*", nil

	case "process.file.mode":
		return "*", nil

	case "process.file.mount_id":
		return "*", nil

	case "process.file.name":
		return "*", nil

	case "process.file.path":
		return "*", nil

	case "process.file.uid":
		return "*", nil

	case "process.file.user":
		return "*", nil

	case "process.fsgid":
		return "*", nil

	case "process.fsgroup":
		return "*", nil

	case "process.fsuid":
		return "*", nil

	case "process.fsuser":
		return "*", nil

	case "process.gid":
		return "*", nil

	case "process.group":
		return "*", nil

	case "process.pid":
		return "*", nil

	case "process.ppid":
		return "*", nil

	case "process.tid":
		return "*", nil

	case "process.tty_name":
		return "*", nil

	case "process.uid":
		return "*", nil

	case "process.user":
		return "*", nil

	case "removexattr.file.container_path":
		return "removexattr", nil

	case "removexattr.file.destination.name":
		return "removexattr", nil

	case "removexattr.file.destination.namespace":
		return "removexattr", nil

	case "removexattr.file.filesystem":
		return "removexattr", nil

	case "removexattr.file.gid":
		return "removexattr", nil

	case "removexattr.file.group":
		return "removexattr", nil

	case "removexattr.file.in_upper_layer":
		return "removexattr", nil

	case "removexattr.file.inode":
		return "removexattr", nil

	case "removexattr.file.mode":
		return "removexattr", nil

	case "removexattr.file.mount_id":
		return "removexattr", nil

	case "removexattr.file.name":
		return "removexattr", nil

	case "removexattr.file.path":
		return "removexattr", nil

	case "removexattr.file.uid":
		return "removexattr", nil

	case "removexattr.file.user":
		return "removexattr", nil

	case "removexattr.retval":
		return "removexattr", nil

	case "rename.file.container_path":
		return "rename", nil

	case "rename.file.destination.container_path":
		return "rename", nil

	case "rename.file.destination.filesystem":
		return "rename", nil

	case "rename.file.destination.gid":
		return "rename", nil

	case "rename.file.destination.group":
		return "rename", nil

	case "rename.file.destination.in_upper_layer":
		return "rename", nil

	case "rename.file.destination.inode":
		return "rename", nil

	case "rename.file.destination.mode":
		return "rename", nil

	case "rename.file.destination.mount_id":
		return "rename", nil

	case "rename.file.destination.name":
		return "rename", nil

	case "rename.file.destination.path":
		return "rename", nil

	case "rename.file.destination.uid":
		return "rename", nil

	case "rename.file.destination.user":
		return "rename", nil

	case "rename.file.filesystem":
		return "rename", nil

	case "rename.file.gid":
		return "rename", nil

	case "rename.file.group":
		return "rename", nil

	case "rename.file.in_upper_layer":
		return "rename", nil

	case "rename.file.inode":
		return "rename", nil

	case "rename.file.mode":
		return "rename", nil

	case "rename.file.mount_id":
		return "rename", nil

	case "rename.file.name":
		return "rename", nil

	case "rename.file.path":
		return "rename", nil

	case "rename.file.uid":
		return "rename", nil

	case "rename.file.user":
		return "rename", nil

	case "rename.retval":
		return "rename", nil

	case "rmdir.file.container_path":
		return "rmdir", nil

	case "rmdir.file.filesystem":
		return "rmdir", nil

	case "rmdir.file.gid":
		return "rmdir", nil

	case "rmdir.file.group":
		return "rmdir", nil

	case "rmdir.file.in_upper_layer":
		return "rmdir", nil

	case "rmdir.file.inode":
		return "rmdir", nil

	case "rmdir.file.mode":
		return "rmdir", nil

	case "rmdir.file.mount_id":
		return "rmdir", nil

	case "rmdir.file.name":
		return "rmdir", nil

	case "rmdir.file.path":
		return "rmdir", nil

	case "rmdir.file.uid":
		return "rmdir", nil

	case "rmdir.file.user":
		return "rmdir", nil

	case "rmdir.retval":
		return "rmdir", nil

	case "setgid.egid":
		return "setgid", nil

	case "setgid.egroup":
		return "setgid", nil

	case "setgid.fsgid":
		return "setgid", nil

	case "setgid.fsgroup":
		return "setgid", nil

	case "setgid.gid":
		return "setgid", nil

	case "setgid.group":
		return "setgid", nil

	case "setuid.euid":
		return "setuid", nil

	case "setuid.euser":
		return "setuid", nil

	case "setuid.fsuid":
		return "setuid", nil

	case "setuid.fsuser":
		return "setuid", nil

	case "setuid.uid":
		return "setuid", nil

	case "setuid.user":
		return "setuid", nil

	case "setxattr.file.container_path":
		return "setxattr", nil

	case "setxattr.file.destination.name":
		return "setxattr", nil

	case "setxattr.file.destination.namespace":
		return "setxattr", nil

	case "setxattr.file.filesystem":
		return "setxattr", nil

	case "setxattr.file.gid":
		return "setxattr", nil

	case "setxattr.file.group":
		return "setxattr", nil

	case "setxattr.file.in_upper_layer":
		return "setxattr", nil

	case "setxattr.file.inode":
		return "setxattr", nil

	case "setxattr.file.mode":
		return "setxattr", nil

	case "setxattr.file.mount_id":
		return "setxattr", nil

	case "setxattr.file.name":
		return "setxattr", nil

	case "setxattr.file.path":
		return "setxattr", nil

	case "setxattr.file.uid":
		return "setxattr", nil

	case "setxattr.file.user":
		return "setxattr", nil

	case "setxattr.retval":
		return "setxattr", nil

	case "unlink.file.container_path":
		return "unlink", nil

	case "unlink.file.filesystem":
		return "unlink", nil

	case "unlink.file.gid":
		return "unlink", nil

	case "unlink.file.group":
		return "unlink", nil

	case "unlink.file.in_upper_layer":
		return "unlink", nil

	case "unlink.file.inode":
		return "unlink", nil

	case "unlink.file.mode":
		return "unlink", nil

	case "unlink.file.mount_id":
		return "unlink", nil

	case "unlink.file.name":
		return "unlink", nil

	case "unlink.file.path":
		return "unlink", nil

	case "unlink.file.uid":
		return "unlink", nil

	case "unlink.file.user":
		return "unlink", nil

	case "unlink.retval":
		return "unlink", nil

	case "utimes.file.container_path":
		return "utimes", nil

	case "utimes.file.filesystem":
		return "utimes", nil

	case "utimes.file.gid":
		return "utimes", nil

	case "utimes.file.group":
		return "utimes", nil

	case "utimes.file.in_upper_layer":
		return "utimes", nil

	case "utimes.file.inode":
		return "utimes", nil

	case "utimes.file.mode":
		return "utimes", nil

	case "utimes.file.mount_id":
		return "utimes", nil

	case "utimes.file.name":
		return "utimes", nil

	case "utimes.file.path":
		return "utimes", nil

	case "utimes.file.uid":
		return "utimes", nil

	case "utimes.file.user":
		return "utimes", nil

	case "utimes.retval":
		return "utimes", nil

	}

	return "", &eval.ErrFieldNotFound{Field: field}
}

func (e *Event) GetFieldType(field eval.Field) (reflect.Kind, error) {
	switch field {

	case "capset.cap_effective":

		return reflect.Int, nil

	case "capset.cap_permitted":

		return reflect.Int, nil

	case "chmod.file.container_path":

		return reflect.String, nil

	case "chmod.file.destination.mode":

		return reflect.Int, nil

	case "chmod.file.filesystem":

		return reflect.String, nil

	case "chmod.file.gid":

		return reflect.Int, nil

	case "chmod.file.group":

		return reflect.String, nil

	case "chmod.file.in_upper_layer":

		return reflect.Bool, nil

	case "chmod.file.inode":

		return reflect.Int, nil

	case "chmod.file.mode":

		return reflect.Int, nil

	case "chmod.file.mount_id":

		return reflect.Int, nil

	case "chmod.file.name":

		return reflect.String, nil

	case "chmod.file.path":

		return reflect.String, nil

	case "chmod.file.uid":

		return reflect.Int, nil

	case "chmod.file.user":

		return reflect.String, nil

	case "chmod.retval":

		return reflect.Int, nil

	case "chown.file.container_path":

		return reflect.String, nil

	case "chown.file.destination.gid":

		return reflect.Int, nil

	case "chown.file.destination.group":

		return reflect.String, nil

	case "chown.file.destination.uid":

		return reflect.Int, nil

	case "chown.file.destination.user":

		return reflect.String, nil

	case "chown.file.filesystem":

		return reflect.String, nil

	case "chown.file.gid":

		return reflect.Int, nil

	case "chown.file.group":

		return reflect.String, nil

	case "chown.file.in_upper_layer":

		return reflect.Bool, nil

	case "chown.file.inode":

		return reflect.Int, nil

	case "chown.file.mode":

		return reflect.Int, nil

	case "chown.file.mount_id":

		return reflect.Int, nil

	case "chown.file.name":

		return reflect.String, nil

	case "chown.file.path":

		return reflect.String, nil

	case "chown.file.uid":

		return reflect.Int, nil

	case "chown.file.user":

		return reflect.String, nil

	case "chown.retval":

		return reflect.Int, nil

	case "container.id":

		return reflect.String, nil

	case "exec.args":

		return reflect.String, nil

	case "exec.args_truncated":

		return reflect.Bool, nil

	case "exec.cap_effective":

		return reflect.Int, nil

	case "exec.cap_permitted":

		return reflect.Int, nil

	case "exec.comm":

		return reflect.String, nil

	case "exec.cookie":

		return reflect.Int, nil

	case "exec.egid":

		return reflect.Int, nil

	case "exec.egroup":

		return reflect.String, nil

	case "exec.envs":

		return reflect.String, nil

	case "exec.envs_truncated":

		return reflect.Bool, nil

	case "exec.euid":

		return reflect.Int, nil

	case "exec.euser":

		return reflect.String, nil

	case "exec.file.container_path":

		return reflect.String, nil

	case "exec.file.filesystem":

		return reflect.String, nil

	case "exec.file.gid":

		return reflect.Int, nil

	case "exec.file.group":

		return reflect.String, nil

	case "exec.file.inode":

		return reflect.Int, nil

	case "exec.file.mode":

		return reflect.Int, nil

	case "exec.file.mount_id":

		return reflect.Int, nil

	case "exec.file.name":

		return reflect.String, nil

	case "exec.file.path":

		return reflect.String, nil

	case "exec.file.uid":

		return reflect.Int, nil

	case "exec.file.user":

		return reflect.String, nil

	case "exec.fsgid":

		return reflect.Int, nil

	case "exec.fsgroup":

		return reflect.String, nil

	case "exec.fsuid":

		return reflect.Int, nil

	case "exec.fsuser":

		return reflect.String, nil

	case "exec.gid":

		return reflect.Int, nil

	case "exec.group":

		return reflect.String, nil

	case "exec.ppid":

		return reflect.Int, nil

	case "exec.tty_name":

		return reflect.String, nil

	case "exec.uid":

		return reflect.Int, nil

	case "exec.user":

		return reflect.String, nil

	case "link.file.container_path":

		return reflect.String, nil

	case "link.file.destination.container_path":

		return reflect.String, nil

	case "link.file.destination.filesystem":

		return reflect.String, nil

	case "link.file.destination.gid":

		return reflect.Int, nil

	case "link.file.destination.group":

		return reflect.String, nil

	case "link.file.destination.in_upper_layer":

		return reflect.Bool, nil

	case "link.file.destination.inode":

		return reflect.Int, nil

	case "link.file.destination.mode":

		return reflect.Int, nil

	case "link.file.destination.mount_id":

		return reflect.Int, nil

	case "link.file.destination.name":

		return reflect.String, nil

	case "link.file.destination.path":

		return reflect.String, nil

	case "link.file.destination.uid":

		return reflect.Int, nil

	case "link.file.destination.user":

		return reflect.String, nil

	case "link.file.filesystem":

		return reflect.String, nil

	case "link.file.gid":

		return reflect.Int, nil

	case "link.file.group":

		return reflect.String, nil

	case "link.file.in_upper_layer":

		return reflect.Bool, nil

	case "link.file.inode":

		return reflect.Int, nil

	case "link.file.mode":

		return reflect.Int, nil

	case "link.file.mount_id":

		return reflect.Int, nil

	case "link.file.name":

		return reflect.String, nil

	case "link.file.path":

		return reflect.String, nil

	case "link.file.uid":

		return reflect.Int, nil

	case "link.file.user":

		return reflect.String, nil

	case "link.retval":

		return reflect.Int, nil

	case "mkdir.file.container_path":

		return reflect.String, nil

	case "mkdir.file.destination.mode":

		return reflect.Int, nil

	case "mkdir.file.filesystem":

		return reflect.String, nil

	case "mkdir.file.gid":

		return reflect.Int, nil

	case "mkdir.file.group":

		return reflect.String, nil

	case "mkdir.file.in_upper_layer":

		return reflect.Bool, nil

	case "mkdir.file.inode":

		return reflect.Int, nil

	case "mkdir.file.mode":

		return reflect.Int, nil

	case "mkdir.file.mount_id":

		return reflect.Int, nil

	case "mkdir.file.name":

		return reflect.String, nil

	case "mkdir.file.path":

		return reflect.String, nil

	case "mkdir.file.uid":

		return reflect.Int, nil

	case "mkdir.file.user":

		return reflect.String, nil

	case "mkdir.retval":

		return reflect.Int, nil

	case "open.file.container_path":

		return reflect.String, nil

	case "open.file.destination.mode":

		return reflect.Int, nil

	case "open.file.filesystem":

		return reflect.String, nil

	case "open.file.gid":

		return reflect.Int, nil

	case "open.file.group":

		return reflect.String, nil

	case "open.file.in_upper_layer":

		return reflect.Bool, nil

	case "open.file.inode":

		return reflect.Int, nil

	case "open.file.mode":

		return reflect.Int, nil

	case "open.file.mount_id":

		return reflect.Int, nil

	case "open.file.name":

		return reflect.String, nil

	case "open.file.path":

		return reflect.String, nil

	case "open.file.uid":

		return reflect.Int, nil

	case "open.file.user":

		return reflect.String, nil

	case "open.flags":

		return reflect.Int, nil

	case "open.retval":

		return reflect.Int, nil

	case "process.ancestors.cap_effective":

		return reflect.Int, nil

	case "process.ancestors.cap_permitted":

		return reflect.Int, nil

	case "process.ancestors.comm":

		return reflect.String, nil

	case "process.ancestors.cookie":

		return reflect.Int, nil

	case "process.ancestors.egid":

		return reflect.Int, nil

	case "process.ancestors.egroup":

		return reflect.String, nil

	case "process.ancestors.euid":

		return reflect.Int, nil

	case "process.ancestors.euser":

		return reflect.String, nil

	case "process.ancestors.file.container_path":

		return reflect.String, nil

	case "process.ancestors.file.filesystem":

		return reflect.String, nil

	case "process.ancestors.file.gid":

		return reflect.Int, nil

	case "process.ancestors.file.group":

		return reflect.String, nil

	case "process.ancestors.file.inode":

		return reflect.Int, nil

	case "process.ancestors.file.mode":

		return reflect.Int, nil

	case "process.ancestors.file.mount_id":

		return reflect.Int, nil

	case "process.ancestors.file.name":

		return reflect.String, nil

	case "process.ancestors.file.path":

		return reflect.String, nil

	case "process.ancestors.file.uid":

		return reflect.Int, nil

	case "process.ancestors.file.user":

		return reflect.String, nil

	case "process.ancestors.fsgid":

		return reflect.Int, nil

	case "process.ancestors.fsgroup":

		return reflect.String, nil

	case "process.ancestors.fsuid":

		return reflect.Int, nil

	case "process.ancestors.fsuser":

		return reflect.String, nil

	case "process.ancestors.gid":

		return reflect.Int, nil

	case "process.ancestors.group":

		return reflect.String, nil

	case "process.ancestors.id":

		return reflect.String, nil

	case "process.ancestors.pid":

		return reflect.Int, nil

	case "process.ancestors.ppid":

		return reflect.Int, nil

	case "process.ancestors.tid":

		return reflect.Int, nil

	case "process.ancestors.tty_name":

		return reflect.String, nil

	case "process.ancestors.uid":

		return reflect.Int, nil

	case "process.ancestors.user":

		return reflect.String, nil

	case "process.cap_effective":

		return reflect.Int, nil

	case "process.cap_permitted":

		return reflect.Int, nil

	case "process.comm":

		return reflect.String, nil

	case "process.cookie":

		return reflect.Int, nil

	case "process.egid":

		return reflect.Int, nil

	case "process.egroup":

		return reflect.String, nil

	case "process.euid":

		return reflect.Int, nil

	case "process.euser":

		return reflect.String, nil

	case "process.file.container_path":

		return reflect.String, nil

	case "process.file.filesystem":

		return reflect.String, nil

	case "process.file.gid":

		return reflect.Int, nil

	case "process.file.group":

		return reflect.String, nil

	case "process.file.inode":

		return reflect.Int, nil

	case "process.file.mode":

		return reflect.Int, nil

	case "process.file.mount_id":

		return reflect.Int, nil

	case "process.file.name":

		return reflect.String, nil

	case "process.file.path":

		return reflect.String, nil

	case "process.file.uid":

		return reflect.Int, nil

	case "process.file.user":

		return reflect.String, nil

	case "process.fsgid":

		return reflect.Int, nil

	case "process.fsgroup":

		return reflect.String, nil

	case "process.fsuid":

		return reflect.Int, nil

	case "process.fsuser":

		return reflect.String, nil

	case "process.gid":

		return reflect.Int, nil

	case "process.group":

		return reflect.String, nil

	case "process.pid":

		return reflect.Int, nil

	case "process.ppid":

		return reflect.Int, nil

	case "process.tid":

		return reflect.Int, nil

	case "process.tty_name":

		return reflect.String, nil

	case "process.uid":

		return reflect.Int, nil

	case "process.user":

		return reflect.String, nil

	case "removexattr.file.container_path":

		return reflect.String, nil

	case "removexattr.file.destination.name":

		return reflect.String, nil

	case "removexattr.file.destination.namespace":

		return reflect.String, nil

	case "removexattr.file.filesystem":

		return reflect.String, nil

	case "removexattr.file.gid":

		return reflect.Int, nil

	case "removexattr.file.group":

		return reflect.String, nil

	case "removexattr.file.in_upper_layer":

		return reflect.Bool, nil

	case "removexattr.file.inode":

		return reflect.Int, nil

	case "removexattr.file.mode":

		return reflect.Int, nil

	case "removexattr.file.mount_id":

		return reflect.Int, nil

	case "removexattr.file.name":

		return reflect.String, nil

	case "removexattr.file.path":

		return reflect.String, nil

	case "removexattr.file.uid":

		return reflect.Int, nil

	case "removexattr.file.user":

		return reflect.String, nil

	case "removexattr.retval":

		return reflect.Int, nil

	case "rename.file.container_path":

		return reflect.String, nil

	case "rename.file.destination.container_path":

		return reflect.String, nil

	case "rename.file.destination.filesystem":

		return reflect.String, nil

	case "rename.file.destination.gid":

		return reflect.Int, nil

	case "rename.file.destination.group":

		return reflect.String, nil

	case "rename.file.destination.in_upper_layer":

		return reflect.Bool, nil

	case "rename.file.destination.inode":

		return reflect.Int, nil

	case "rename.file.destination.mode":

		return reflect.Int, nil

	case "rename.file.destination.mount_id":

		return reflect.Int, nil

	case "rename.file.destination.name":

		return reflect.String, nil

	case "rename.file.destination.path":

		return reflect.String, nil

	case "rename.file.destination.uid":

		return reflect.Int, nil

	case "rename.file.destination.user":

		return reflect.String, nil

	case "rename.file.filesystem":

		return reflect.String, nil

	case "rename.file.gid":

		return reflect.Int, nil

	case "rename.file.group":

		return reflect.String, nil

	case "rename.file.in_upper_layer":

		return reflect.Bool, nil

	case "rename.file.inode":

		return reflect.Int, nil

	case "rename.file.mode":

		return reflect.Int, nil

	case "rename.file.mount_id":

		return reflect.Int, nil

	case "rename.file.name":

		return reflect.String, nil

	case "rename.file.path":

		return reflect.String, nil

	case "rename.file.uid":

		return reflect.Int, nil

	case "rename.file.user":

		return reflect.String, nil

	case "rename.retval":

		return reflect.Int, nil

	case "rmdir.file.container_path":

		return reflect.String, nil

	case "rmdir.file.filesystem":

		return reflect.String, nil

	case "rmdir.file.gid":

		return reflect.Int, nil

	case "rmdir.file.group":

		return reflect.String, nil

	case "rmdir.file.in_upper_layer":

		return reflect.Bool, nil

	case "rmdir.file.inode":

		return reflect.Int, nil

	case "rmdir.file.mode":

		return reflect.Int, nil

	case "rmdir.file.mount_id":

		return reflect.Int, nil

	case "rmdir.file.name":

		return reflect.String, nil

	case "rmdir.file.path":

		return reflect.String, nil

	case "rmdir.file.uid":

		return reflect.Int, nil

	case "rmdir.file.user":

		return reflect.String, nil

	case "rmdir.retval":

		return reflect.Int, nil

	case "setgid.egid":

		return reflect.Int, nil

	case "setgid.egroup":

		return reflect.String, nil

	case "setgid.fsgid":

		return reflect.Int, nil

	case "setgid.fsgroup":

		return reflect.String, nil

	case "setgid.gid":

		return reflect.Int, nil

	case "setgid.group":

		return reflect.String, nil

	case "setuid.euid":

		return reflect.Int, nil

	case "setuid.euser":

		return reflect.String, nil

	case "setuid.fsuid":

		return reflect.Int, nil

	case "setuid.fsuser":

		return reflect.String, nil

	case "setuid.uid":

		return reflect.Int, nil

	case "setuid.user":

		return reflect.String, nil

	case "setxattr.file.container_path":

		return reflect.String, nil

	case "setxattr.file.destination.name":

		return reflect.String, nil

	case "setxattr.file.destination.namespace":

		return reflect.String, nil

	case "setxattr.file.filesystem":

		return reflect.String, nil

	case "setxattr.file.gid":

		return reflect.Int, nil

	case "setxattr.file.group":

		return reflect.String, nil

	case "setxattr.file.in_upper_layer":

		return reflect.Bool, nil

	case "setxattr.file.inode":

		return reflect.Int, nil

	case "setxattr.file.mode":

		return reflect.Int, nil

	case "setxattr.file.mount_id":

		return reflect.Int, nil

	case "setxattr.file.name":

		return reflect.String, nil

	case "setxattr.file.path":

		return reflect.String, nil

	case "setxattr.file.uid":

		return reflect.Int, nil

	case "setxattr.file.user":

		return reflect.String, nil

	case "setxattr.retval":

		return reflect.Int, nil

	case "unlink.file.container_path":

		return reflect.String, nil

	case "unlink.file.filesystem":

		return reflect.String, nil

	case "unlink.file.gid":

		return reflect.Int, nil

	case "unlink.file.group":

		return reflect.String, nil

	case "unlink.file.in_upper_layer":

		return reflect.Bool, nil

	case "unlink.file.inode":

		return reflect.Int, nil

	case "unlink.file.mode":

		return reflect.Int, nil

	case "unlink.file.mount_id":

		return reflect.Int, nil

	case "unlink.file.name":

		return reflect.String, nil

	case "unlink.file.path":

		return reflect.String, nil

	case "unlink.file.uid":

		return reflect.Int, nil

	case "unlink.file.user":

		return reflect.String, nil

	case "unlink.retval":

		return reflect.Int, nil

	case "utimes.file.container_path":

		return reflect.String, nil

	case "utimes.file.filesystem":

		return reflect.String, nil

	case "utimes.file.gid":

		return reflect.Int, nil

	case "utimes.file.group":

		return reflect.String, nil

	case "utimes.file.in_upper_layer":

		return reflect.Bool, nil

	case "utimes.file.inode":

		return reflect.Int, nil

	case "utimes.file.mode":

		return reflect.Int, nil

	case "utimes.file.mount_id":

		return reflect.Int, nil

	case "utimes.file.name":

		return reflect.String, nil

	case "utimes.file.path":

		return reflect.String, nil

	case "utimes.file.uid":

		return reflect.Int, nil

	case "utimes.file.user":

		return reflect.String, nil

	case "utimes.retval":

		return reflect.Int, nil

	}

	return reflect.Invalid, &eval.ErrFieldNotFound{Field: field}
}

func (e *Event) SetFieldValue(field eval.Field, value interface{}) error {
	switch field {

	case "capset.cap_effective":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Capset.CapEffective"}
		}
		e.Capset.CapEffective = uint64(v)
		return nil

	case "capset.cap_permitted":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Capset.CapPermitted"}
		}
		e.Capset.CapPermitted = uint64(v)
		return nil

	case "chmod.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.ContainerPath"}
		}
		e.Chmod.File.ContainerPath = str

		return nil

	case "chmod.file.destination.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.Mode"}
		}
		e.Chmod.Mode = uint32(v)
		return nil

	case "chmod.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.Filesytem"}
		}
		e.Chmod.File.Filesytem = str

		return nil

	case "chmod.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.GID"}
		}
		e.Chmod.File.FileFields.GID = uint32(v)
		return nil

	case "chmod.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.Group"}
		}
		e.Chmod.File.FileFields.Group = str

		return nil

	case "chmod.file.in_upper_layer":

		var ok bool
		if e.Chmod.File.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.InUpperLayer"}
		}
		return nil

	case "chmod.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.Inode"}
		}
		e.Chmod.File.FileFields.Inode = uint64(v)
		return nil

	case "chmod.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.Mode"}
		}
		e.Chmod.File.FileFields.Mode = uint16(v)
		return nil

	case "chmod.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.MountID"}
		}
		e.Chmod.File.FileFields.MountID = uint32(v)
		return nil

	case "chmod.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.BasenameStr"}
		}
		e.Chmod.File.BasenameStr = str

		return nil

	case "chmod.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.PathnameStr"}
		}
		e.Chmod.File.PathnameStr = str

		return nil

	case "chmod.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.UID"}
		}
		e.Chmod.File.FileFields.UID = uint32(v)
		return nil

	case "chmod.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.User"}
		}
		e.Chmod.File.FileFields.User = str

		return nil

	case "chmod.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.SyscallEvent.Retval"}
		}
		e.Chmod.SyscallEvent.Retval = int64(v)
		return nil

	case "chown.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.ContainerPath"}
		}
		e.Chown.File.ContainerPath = str

		return nil

	case "chown.file.destination.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.GID"}
		}
		e.Chown.GID = uint32(v)
		return nil

	case "chown.file.destination.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.Group"}
		}
		e.Chown.Group = str

		return nil

	case "chown.file.destination.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.UID"}
		}
		e.Chown.UID = uint32(v)
		return nil

	case "chown.file.destination.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.User"}
		}
		e.Chown.User = str

		return nil

	case "chown.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.Filesytem"}
		}
		e.Chown.File.Filesytem = str

		return nil

	case "chown.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.GID"}
		}
		e.Chown.File.FileFields.GID = uint32(v)
		return nil

	case "chown.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.Group"}
		}
		e.Chown.File.FileFields.Group = str

		return nil

	case "chown.file.in_upper_layer":

		var ok bool
		if e.Chown.File.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.InUpperLayer"}
		}
		return nil

	case "chown.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.Inode"}
		}
		e.Chown.File.FileFields.Inode = uint64(v)
		return nil

	case "chown.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.Mode"}
		}
		e.Chown.File.FileFields.Mode = uint16(v)
		return nil

	case "chown.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.MountID"}
		}
		e.Chown.File.FileFields.MountID = uint32(v)
		return nil

	case "chown.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.BasenameStr"}
		}
		e.Chown.File.BasenameStr = str

		return nil

	case "chown.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.PathnameStr"}
		}
		e.Chown.File.PathnameStr = str

		return nil

	case "chown.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.UID"}
		}
		e.Chown.File.FileFields.UID = uint32(v)
		return nil

	case "chown.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.User"}
		}
		e.Chown.File.FileFields.User = str

		return nil

	case "chown.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.SyscallEvent.Retval"}
		}
		e.Chown.SyscallEvent.Retval = int64(v)
		return nil

	case "container.id":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ContainerContext.ID"}
		}
		e.ContainerContext.ID = str

		return nil

	case "exec.args":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Args"}
		}
		e.Exec.Args = str

		return nil

	case "exec.args_truncated":

		var ok bool
		if e.Exec.ArgsTruncated, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.ArgsTruncated"}
		}
		return nil

	case "exec.cap_effective":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.CapEffective"}
		}
		e.Exec.Process.Credentials.CapEffective = uint64(v)
		return nil

	case "exec.cap_permitted":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.CapPermitted"}
		}
		e.Exec.Process.Credentials.CapPermitted = uint64(v)
		return nil

	case "exec.comm":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Comm"}
		}
		e.Exec.Process.Comm = str

		return nil

	case "exec.cookie":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Cookie"}
		}
		e.Exec.Process.Cookie = uint32(v)
		return nil

	case "exec.egid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EGID"}
		}
		e.Exec.Process.Credentials.EGID = uint32(v)
		return nil

	case "exec.egroup":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EGroup"}
		}
		e.Exec.Process.Credentials.EGroup = str

		return nil

	case "exec.envs":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Envs"}
		}
		e.Exec.Envs = str

		return nil

	case "exec.envs_truncated":

		var ok bool
		if e.Exec.EnvsTruncated, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.EnvsTruncated"}
		}
		return nil

	case "exec.euid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EUID"}
		}
		e.Exec.Process.Credentials.EUID = uint32(v)
		return nil

	case "exec.euser":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EUser"}
		}
		e.Exec.Process.Credentials.EUser = str

		return nil

	case "exec.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.ContainerPath"}
		}
		e.Exec.Process.ContainerPath = str

		return nil

	case "exec.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Filesystem"}
		}
		e.Exec.Process.Filesystem = str

		return nil

	case "exec.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileFields.GID"}
		}
		e.Exec.Process.FileFields.GID = uint32(v)
		return nil

	case "exec.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileFields.Group"}
		}
		e.Exec.Process.FileFields.Group = str

		return nil

	case "exec.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileFields.Inode"}
		}
		e.Exec.Process.FileFields.Inode = uint64(v)
		return nil

	case "exec.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileFields.Mode"}
		}
		e.Exec.Process.FileFields.Mode = uint16(v)
		return nil

	case "exec.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileFields.MountID"}
		}
		e.Exec.Process.FileFields.MountID = uint32(v)
		return nil

	case "exec.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.BasenameStr"}
		}
		e.Exec.Process.BasenameStr = str

		return nil

	case "exec.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PathnameStr"}
		}
		e.Exec.Process.PathnameStr = str

		return nil

	case "exec.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileFields.UID"}
		}
		e.Exec.Process.FileFields.UID = uint32(v)
		return nil

	case "exec.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileFields.User"}
		}
		e.Exec.Process.FileFields.User = str

		return nil

	case "exec.fsgid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSGID"}
		}
		e.Exec.Process.Credentials.FSGID = uint32(v)
		return nil

	case "exec.fsgroup":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSGroup"}
		}
		e.Exec.Process.Credentials.FSGroup = str

		return nil

	case "exec.fsuid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSUID"}
		}
		e.Exec.Process.Credentials.FSUID = uint32(v)
		return nil

	case "exec.fsuser":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSUser"}
		}
		e.Exec.Process.Credentials.FSUser = str

		return nil

	case "exec.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.GID"}
		}
		e.Exec.Process.Credentials.GID = uint32(v)
		return nil

	case "exec.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.Group"}
		}
		e.Exec.Process.Credentials.Group = str

		return nil

	case "exec.ppid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PPid"}
		}
		e.Exec.Process.PPid = uint32(v)
		return nil

	case "exec.tty_name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.TTYName"}
		}
		e.Exec.Process.TTYName = str

		return nil

	case "exec.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.UID"}
		}
		e.Exec.Process.Credentials.UID = uint32(v)
		return nil

	case "exec.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.User"}
		}
		e.Exec.Process.Credentials.User = str

		return nil

	case "link.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.ContainerPath"}
		}
		e.Link.Source.ContainerPath = str

		return nil

	case "link.file.destination.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.ContainerPath"}
		}
		e.Link.Target.ContainerPath = str

		return nil

	case "link.file.destination.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.Filesytem"}
		}
		e.Link.Target.Filesytem = str

		return nil

	case "link.file.destination.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.GID"}
		}
		e.Link.Target.FileFields.GID = uint32(v)
		return nil

	case "link.file.destination.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.Group"}
		}
		e.Link.Target.FileFields.Group = str

		return nil

	case "link.file.destination.in_upper_layer":

		var ok bool
		if e.Link.Target.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.InUpperLayer"}
		}
		return nil

	case "link.file.destination.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.Inode"}
		}
		e.Link.Target.FileFields.Inode = uint64(v)
		return nil

	case "link.file.destination.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.Mode"}
		}
		e.Link.Target.FileFields.Mode = uint16(v)
		return nil

	case "link.file.destination.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.MountID"}
		}
		e.Link.Target.FileFields.MountID = uint32(v)
		return nil

	case "link.file.destination.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.BasenameStr"}
		}
		e.Link.Target.BasenameStr = str

		return nil

	case "link.file.destination.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.PathnameStr"}
		}
		e.Link.Target.PathnameStr = str

		return nil

	case "link.file.destination.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.UID"}
		}
		e.Link.Target.FileFields.UID = uint32(v)
		return nil

	case "link.file.destination.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.User"}
		}
		e.Link.Target.FileFields.User = str

		return nil

	case "link.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.Filesytem"}
		}
		e.Link.Source.Filesytem = str

		return nil

	case "link.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.GID"}
		}
		e.Link.Source.FileFields.GID = uint32(v)
		return nil

	case "link.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.Group"}
		}
		e.Link.Source.FileFields.Group = str

		return nil

	case "link.file.in_upper_layer":

		var ok bool
		if e.Link.Source.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.InUpperLayer"}
		}
		return nil

	case "link.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.Inode"}
		}
		e.Link.Source.FileFields.Inode = uint64(v)
		return nil

	case "link.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.Mode"}
		}
		e.Link.Source.FileFields.Mode = uint16(v)
		return nil

	case "link.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.MountID"}
		}
		e.Link.Source.FileFields.MountID = uint32(v)
		return nil

	case "link.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.BasenameStr"}
		}
		e.Link.Source.BasenameStr = str

		return nil

	case "link.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.PathnameStr"}
		}
		e.Link.Source.PathnameStr = str

		return nil

	case "link.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.UID"}
		}
		e.Link.Source.FileFields.UID = uint32(v)
		return nil

	case "link.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.User"}
		}
		e.Link.Source.FileFields.User = str

		return nil

	case "link.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.SyscallEvent.Retval"}
		}
		e.Link.SyscallEvent.Retval = int64(v)
		return nil

	case "mkdir.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.ContainerPath"}
		}
		e.Mkdir.File.ContainerPath = str

		return nil

	case "mkdir.file.destination.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.Mode"}
		}
		e.Mkdir.Mode = uint32(v)
		return nil

	case "mkdir.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.Filesytem"}
		}
		e.Mkdir.File.Filesytem = str

		return nil

	case "mkdir.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.GID"}
		}
		e.Mkdir.File.FileFields.GID = uint32(v)
		return nil

	case "mkdir.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.Group"}
		}
		e.Mkdir.File.FileFields.Group = str

		return nil

	case "mkdir.file.in_upper_layer":

		var ok bool
		if e.Mkdir.File.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.InUpperLayer"}
		}
		return nil

	case "mkdir.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.Inode"}
		}
		e.Mkdir.File.FileFields.Inode = uint64(v)
		return nil

	case "mkdir.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.Mode"}
		}
		e.Mkdir.File.FileFields.Mode = uint16(v)
		return nil

	case "mkdir.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.MountID"}
		}
		e.Mkdir.File.FileFields.MountID = uint32(v)
		return nil

	case "mkdir.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.BasenameStr"}
		}
		e.Mkdir.File.BasenameStr = str

		return nil

	case "mkdir.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.PathnameStr"}
		}
		e.Mkdir.File.PathnameStr = str

		return nil

	case "mkdir.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.UID"}
		}
		e.Mkdir.File.FileFields.UID = uint32(v)
		return nil

	case "mkdir.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.User"}
		}
		e.Mkdir.File.FileFields.User = str

		return nil

	case "mkdir.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.SyscallEvent.Retval"}
		}
		e.Mkdir.SyscallEvent.Retval = int64(v)
		return nil

	case "open.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.ContainerPath"}
		}
		e.Open.File.ContainerPath = str

		return nil

	case "open.file.destination.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.Mode"}
		}
		e.Open.Mode = uint32(v)
		return nil

	case "open.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.Filesytem"}
		}
		e.Open.File.Filesytem = str

		return nil

	case "open.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.GID"}
		}
		e.Open.File.FileFields.GID = uint32(v)
		return nil

	case "open.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.Group"}
		}
		e.Open.File.FileFields.Group = str

		return nil

	case "open.file.in_upper_layer":

		var ok bool
		if e.Open.File.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.InUpperLayer"}
		}
		return nil

	case "open.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.Inode"}
		}
		e.Open.File.FileFields.Inode = uint64(v)
		return nil

	case "open.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.Mode"}
		}
		e.Open.File.FileFields.Mode = uint16(v)
		return nil

	case "open.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.MountID"}
		}
		e.Open.File.FileFields.MountID = uint32(v)
		return nil

	case "open.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.BasenameStr"}
		}
		e.Open.File.BasenameStr = str

		return nil

	case "open.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.PathnameStr"}
		}
		e.Open.File.PathnameStr = str

		return nil

	case "open.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.UID"}
		}
		e.Open.File.FileFields.UID = uint32(v)
		return nil

	case "open.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.User"}
		}
		e.Open.File.FileFields.User = str

		return nil

	case "open.flags":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.Flags"}
		}
		e.Open.Flags = uint32(v)
		return nil

	case "open.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.SyscallEvent.Retval"}
		}
		e.Open.SyscallEvent.Retval = int64(v)
		return nil

	case "process.ancestors.cap_effective":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.CapEffective"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.CapEffective = uint64(v)
		return nil

	case "process.ancestors.cap_permitted":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.CapPermitted"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.CapPermitted = uint64(v)
		return nil

	case "process.ancestors.comm":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Comm"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Comm = str

		return nil

	case "process.ancestors.cookie":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Cookie"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Cookie = uint32(v)
		return nil

	case "process.ancestors.egid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.EGID"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.EGID = uint32(v)
		return nil

	case "process.ancestors.egroup":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.EGroup"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.EGroup = str

		return nil

	case "process.ancestors.euid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.EUID"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.EUID = uint32(v)
		return nil

	case "process.ancestors.euser":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.EUser"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.EUser = str

		return nil

	case "process.ancestors.file.container_path":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.ContainerPath"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.ContainerPath = str

		return nil

	case "process.ancestors.file.filesystem":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Filesystem"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Filesystem = str

		return nil

	case "process.ancestors.file.gid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.FileFields.GID"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.FileFields.GID = uint32(v)
		return nil

	case "process.ancestors.file.group":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.FileFields.Group"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.FileFields.Group = str

		return nil

	case "process.ancestors.file.inode":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.FileFields.Inode"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.FileFields.Inode = uint64(v)
		return nil

	case "process.ancestors.file.mode":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.FileFields.Mode"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.FileFields.Mode = uint16(v)
		return nil

	case "process.ancestors.file.mount_id":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.FileFields.MountID"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.FileFields.MountID = uint32(v)
		return nil

	case "process.ancestors.file.name":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.BasenameStr"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.BasenameStr = str

		return nil

	case "process.ancestors.file.path":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.PathnameStr"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.PathnameStr = str

		return nil

	case "process.ancestors.file.uid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.FileFields.UID"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.FileFields.UID = uint32(v)
		return nil

	case "process.ancestors.file.user":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.FileFields.User"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.FileFields.User = str

		return nil

	case "process.ancestors.fsgid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.FSGID"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.FSGID = uint32(v)
		return nil

	case "process.ancestors.fsgroup":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.FSGroup"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.FSGroup = str

		return nil

	case "process.ancestors.fsuid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.FSUID"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.FSUID = uint32(v)
		return nil

	case "process.ancestors.fsuser":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.FSUser"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.FSUser = str

		return nil

	case "process.ancestors.gid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.GID"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.GID = uint32(v)
		return nil

	case "process.ancestors.group":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.Group"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.Group = str

		return nil

	case "process.ancestors.id":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ContainerContext.ID"}
		}
		e.ProcessContext.Ancestor.ContainerContext.ID = str

		return nil

	case "process.ancestors.pid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Pid"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Pid = uint32(v)
		return nil

	case "process.ancestors.ppid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.PPid"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.PPid = uint32(v)
		return nil

	case "process.ancestors.tid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Tid"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Tid = uint32(v)
		return nil

	case "process.ancestors.tty_name":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.TTYName"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.TTYName = str

		return nil

	case "process.ancestors.uid":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.UID"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.UID = uint32(v)
		return nil

	case "process.ancestors.user":

		if e.ProcessContext.Ancestor == nil {
			e.ProcessContext.Ancestor = &model.ProcessCacheEntry{}
		}

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Ancestor.ProcessContext.Process.Credentials.User"}
		}
		e.ProcessContext.Ancestor.ProcessContext.Process.Credentials.User = str

		return nil

	case "process.cap_effective":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.CapEffective"}
		}
		e.ProcessContext.Process.Credentials.CapEffective = uint64(v)
		return nil

	case "process.cap_permitted":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.CapPermitted"}
		}
		e.ProcessContext.Process.Credentials.CapPermitted = uint64(v)
		return nil

	case "process.comm":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Comm"}
		}
		e.ProcessContext.Process.Comm = str

		return nil

	case "process.cookie":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Cookie"}
		}
		e.ProcessContext.Process.Cookie = uint32(v)
		return nil

	case "process.egid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.EGID"}
		}
		e.ProcessContext.Process.Credentials.EGID = uint32(v)
		return nil

	case "process.egroup":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.EGroup"}
		}
		e.ProcessContext.Process.Credentials.EGroup = str

		return nil

	case "process.euid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.EUID"}
		}
		e.ProcessContext.Process.Credentials.EUID = uint32(v)
		return nil

	case "process.euser":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.EUser"}
		}
		e.ProcessContext.Process.Credentials.EUser = str

		return nil

	case "process.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.ContainerPath"}
		}
		e.ProcessContext.Process.ContainerPath = str

		return nil

	case "process.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Filesystem"}
		}
		e.ProcessContext.Process.Filesystem = str

		return nil

	case "process.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.FileFields.GID"}
		}
		e.ProcessContext.Process.FileFields.GID = uint32(v)
		return nil

	case "process.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.FileFields.Group"}
		}
		e.ProcessContext.Process.FileFields.Group = str

		return nil

	case "process.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.FileFields.Inode"}
		}
		e.ProcessContext.Process.FileFields.Inode = uint64(v)
		return nil

	case "process.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.FileFields.Mode"}
		}
		e.ProcessContext.Process.FileFields.Mode = uint16(v)
		return nil

	case "process.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.FileFields.MountID"}
		}
		e.ProcessContext.Process.FileFields.MountID = uint32(v)
		return nil

	case "process.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.BasenameStr"}
		}
		e.ProcessContext.Process.BasenameStr = str

		return nil

	case "process.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.PathnameStr"}
		}
		e.ProcessContext.Process.PathnameStr = str

		return nil

	case "process.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.FileFields.UID"}
		}
		e.ProcessContext.Process.FileFields.UID = uint32(v)
		return nil

	case "process.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.FileFields.User"}
		}
		e.ProcessContext.Process.FileFields.User = str

		return nil

	case "process.fsgid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.FSGID"}
		}
		e.ProcessContext.Process.Credentials.FSGID = uint32(v)
		return nil

	case "process.fsgroup":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.FSGroup"}
		}
		e.ProcessContext.Process.Credentials.FSGroup = str

		return nil

	case "process.fsuid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.FSUID"}
		}
		e.ProcessContext.Process.Credentials.FSUID = uint32(v)
		return nil

	case "process.fsuser":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.FSUser"}
		}
		e.ProcessContext.Process.Credentials.FSUser = str

		return nil

	case "process.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.GID"}
		}
		e.ProcessContext.Process.Credentials.GID = uint32(v)
		return nil

	case "process.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.Group"}
		}
		e.ProcessContext.Process.Credentials.Group = str

		return nil

	case "process.pid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Pid"}
		}
		e.ProcessContext.Pid = uint32(v)
		return nil

	case "process.ppid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.PPid"}
		}
		e.ProcessContext.Process.PPid = uint32(v)
		return nil

	case "process.tid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Tid"}
		}
		e.ProcessContext.Tid = uint32(v)
		return nil

	case "process.tty_name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.TTYName"}
		}
		e.ProcessContext.Process.TTYName = str

		return nil

	case "process.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.UID"}
		}
		e.ProcessContext.Process.Credentials.UID = uint32(v)
		return nil

	case "process.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ProcessContext.Process.Credentials.User"}
		}
		e.ProcessContext.Process.Credentials.User = str

		return nil

	case "removexattr.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.ContainerPath"}
		}
		e.RemoveXAttr.File.ContainerPath = str

		return nil

	case "removexattr.file.destination.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.Name"}
		}
		e.RemoveXAttr.Name = str

		return nil

	case "removexattr.file.destination.namespace":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.Namespace"}
		}
		e.RemoveXAttr.Namespace = str

		return nil

	case "removexattr.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.Filesytem"}
		}
		e.RemoveXAttr.File.Filesytem = str

		return nil

	case "removexattr.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.GID"}
		}
		e.RemoveXAttr.File.FileFields.GID = uint32(v)
		return nil

	case "removexattr.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.Group"}
		}
		e.RemoveXAttr.File.FileFields.Group = str

		return nil

	case "removexattr.file.in_upper_layer":

		var ok bool
		if e.RemoveXAttr.File.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.InUpperLayer"}
		}
		return nil

	case "removexattr.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.Inode"}
		}
		e.RemoveXAttr.File.FileFields.Inode = uint64(v)
		return nil

	case "removexattr.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.Mode"}
		}
		e.RemoveXAttr.File.FileFields.Mode = uint16(v)
		return nil

	case "removexattr.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.MountID"}
		}
		e.RemoveXAttr.File.FileFields.MountID = uint32(v)
		return nil

	case "removexattr.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.BasenameStr"}
		}
		e.RemoveXAttr.File.BasenameStr = str

		return nil

	case "removexattr.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.PathnameStr"}
		}
		e.RemoveXAttr.File.PathnameStr = str

		return nil

	case "removexattr.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.UID"}
		}
		e.RemoveXAttr.File.FileFields.UID = uint32(v)
		return nil

	case "removexattr.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.User"}
		}
		e.RemoveXAttr.File.FileFields.User = str

		return nil

	case "removexattr.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.SyscallEvent.Retval"}
		}
		e.RemoveXAttr.SyscallEvent.Retval = int64(v)
		return nil

	case "rename.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.ContainerPath"}
		}
		e.Rename.Old.ContainerPath = str

		return nil

	case "rename.file.destination.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.ContainerPath"}
		}
		e.Rename.New.ContainerPath = str

		return nil

	case "rename.file.destination.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.Filesytem"}
		}
		e.Rename.New.Filesytem = str

		return nil

	case "rename.file.destination.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.GID"}
		}
		e.Rename.New.FileFields.GID = uint32(v)
		return nil

	case "rename.file.destination.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.Group"}
		}
		e.Rename.New.FileFields.Group = str

		return nil

	case "rename.file.destination.in_upper_layer":

		var ok bool
		if e.Rename.New.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.InUpperLayer"}
		}
		return nil

	case "rename.file.destination.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.Inode"}
		}
		e.Rename.New.FileFields.Inode = uint64(v)
		return nil

	case "rename.file.destination.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.Mode"}
		}
		e.Rename.New.FileFields.Mode = uint16(v)
		return nil

	case "rename.file.destination.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.MountID"}
		}
		e.Rename.New.FileFields.MountID = uint32(v)
		return nil

	case "rename.file.destination.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.BasenameStr"}
		}
		e.Rename.New.BasenameStr = str

		return nil

	case "rename.file.destination.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.PathnameStr"}
		}
		e.Rename.New.PathnameStr = str

		return nil

	case "rename.file.destination.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.UID"}
		}
		e.Rename.New.FileFields.UID = uint32(v)
		return nil

	case "rename.file.destination.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.User"}
		}
		e.Rename.New.FileFields.User = str

		return nil

	case "rename.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.Filesytem"}
		}
		e.Rename.Old.Filesytem = str

		return nil

	case "rename.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.GID"}
		}
		e.Rename.Old.FileFields.GID = uint32(v)
		return nil

	case "rename.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.Group"}
		}
		e.Rename.Old.FileFields.Group = str

		return nil

	case "rename.file.in_upper_layer":

		var ok bool
		if e.Rename.Old.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.InUpperLayer"}
		}
		return nil

	case "rename.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.Inode"}
		}
		e.Rename.Old.FileFields.Inode = uint64(v)
		return nil

	case "rename.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.Mode"}
		}
		e.Rename.Old.FileFields.Mode = uint16(v)
		return nil

	case "rename.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.MountID"}
		}
		e.Rename.Old.FileFields.MountID = uint32(v)
		return nil

	case "rename.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.BasenameStr"}
		}
		e.Rename.Old.BasenameStr = str

		return nil

	case "rename.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.PathnameStr"}
		}
		e.Rename.Old.PathnameStr = str

		return nil

	case "rename.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.UID"}
		}
		e.Rename.Old.FileFields.UID = uint32(v)
		return nil

	case "rename.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.User"}
		}
		e.Rename.Old.FileFields.User = str

		return nil

	case "rename.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.SyscallEvent.Retval"}
		}
		e.Rename.SyscallEvent.Retval = int64(v)
		return nil

	case "rmdir.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.ContainerPath"}
		}
		e.Rmdir.File.ContainerPath = str

		return nil

	case "rmdir.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.Filesytem"}
		}
		e.Rmdir.File.Filesytem = str

		return nil

	case "rmdir.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.GID"}
		}
		e.Rmdir.File.FileFields.GID = uint32(v)
		return nil

	case "rmdir.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.Group"}
		}
		e.Rmdir.File.FileFields.Group = str

		return nil

	case "rmdir.file.in_upper_layer":

		var ok bool
		if e.Rmdir.File.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.InUpperLayer"}
		}
		return nil

	case "rmdir.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.Inode"}
		}
		e.Rmdir.File.FileFields.Inode = uint64(v)
		return nil

	case "rmdir.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.Mode"}
		}
		e.Rmdir.File.FileFields.Mode = uint16(v)
		return nil

	case "rmdir.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.MountID"}
		}
		e.Rmdir.File.FileFields.MountID = uint32(v)
		return nil

	case "rmdir.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.BasenameStr"}
		}
		e.Rmdir.File.BasenameStr = str

		return nil

	case "rmdir.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.PathnameStr"}
		}
		e.Rmdir.File.PathnameStr = str

		return nil

	case "rmdir.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.UID"}
		}
		e.Rmdir.File.FileFields.UID = uint32(v)
		return nil

	case "rmdir.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.User"}
		}
		e.Rmdir.File.FileFields.User = str

		return nil

	case "rmdir.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.SyscallEvent.Retval"}
		}
		e.Rmdir.SyscallEvent.Retval = int64(v)
		return nil

	case "setgid.egid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.EGID"}
		}
		e.SetGID.EGID = uint32(v)
		return nil

	case "setgid.egroup":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.EGroup"}
		}
		e.SetGID.EGroup = str

		return nil

	case "setgid.fsgid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.FSGID"}
		}
		e.SetGID.FSGID = uint32(v)
		return nil

	case "setgid.fsgroup":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.FSGroup"}
		}
		e.SetGID.FSGroup = str

		return nil

	case "setgid.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.GID"}
		}
		e.SetGID.GID = uint32(v)
		return nil

	case "setgid.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.Group"}
		}
		e.SetGID.Group = str

		return nil

	case "setuid.euid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.EUID"}
		}
		e.SetUID.EUID = uint32(v)
		return nil

	case "setuid.euser":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.EUser"}
		}
		e.SetUID.EUser = str

		return nil

	case "setuid.fsuid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.FSUID"}
		}
		e.SetUID.FSUID = uint32(v)
		return nil

	case "setuid.fsuser":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.FSUser"}
		}
		e.SetUID.FSUser = str

		return nil

	case "setuid.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.UID"}
		}
		e.SetUID.UID = uint32(v)
		return nil

	case "setuid.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.User"}
		}
		e.SetUID.User = str

		return nil

	case "setxattr.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.ContainerPath"}
		}
		e.SetXAttr.File.ContainerPath = str

		return nil

	case "setxattr.file.destination.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.Name"}
		}
		e.SetXAttr.Name = str

		return nil

	case "setxattr.file.destination.namespace":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.Namespace"}
		}
		e.SetXAttr.Namespace = str

		return nil

	case "setxattr.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.Filesytem"}
		}
		e.SetXAttr.File.Filesytem = str

		return nil

	case "setxattr.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.GID"}
		}
		e.SetXAttr.File.FileFields.GID = uint32(v)
		return nil

	case "setxattr.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.Group"}
		}
		e.SetXAttr.File.FileFields.Group = str

		return nil

	case "setxattr.file.in_upper_layer":

		var ok bool
		if e.SetXAttr.File.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.InUpperLayer"}
		}
		return nil

	case "setxattr.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.Inode"}
		}
		e.SetXAttr.File.FileFields.Inode = uint64(v)
		return nil

	case "setxattr.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.Mode"}
		}
		e.SetXAttr.File.FileFields.Mode = uint16(v)
		return nil

	case "setxattr.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.MountID"}
		}
		e.SetXAttr.File.FileFields.MountID = uint32(v)
		return nil

	case "setxattr.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.BasenameStr"}
		}
		e.SetXAttr.File.BasenameStr = str

		return nil

	case "setxattr.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.PathnameStr"}
		}
		e.SetXAttr.File.PathnameStr = str

		return nil

	case "setxattr.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.UID"}
		}
		e.SetXAttr.File.FileFields.UID = uint32(v)
		return nil

	case "setxattr.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.User"}
		}
		e.SetXAttr.File.FileFields.User = str

		return nil

	case "setxattr.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.SyscallEvent.Retval"}
		}
		e.SetXAttr.SyscallEvent.Retval = int64(v)
		return nil

	case "unlink.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.ContainerPath"}
		}
		e.Unlink.File.ContainerPath = str

		return nil

	case "unlink.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.Filesytem"}
		}
		e.Unlink.File.Filesytem = str

		return nil

	case "unlink.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.GID"}
		}
		e.Unlink.File.FileFields.GID = uint32(v)
		return nil

	case "unlink.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.Group"}
		}
		e.Unlink.File.FileFields.Group = str

		return nil

	case "unlink.file.in_upper_layer":

		var ok bool
		if e.Unlink.File.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.InUpperLayer"}
		}
		return nil

	case "unlink.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.Inode"}
		}
		e.Unlink.File.FileFields.Inode = uint64(v)
		return nil

	case "unlink.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.Mode"}
		}
		e.Unlink.File.FileFields.Mode = uint16(v)
		return nil

	case "unlink.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.MountID"}
		}
		e.Unlink.File.FileFields.MountID = uint32(v)
		return nil

	case "unlink.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.BasenameStr"}
		}
		e.Unlink.File.BasenameStr = str

		return nil

	case "unlink.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.PathnameStr"}
		}
		e.Unlink.File.PathnameStr = str

		return nil

	case "unlink.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.UID"}
		}
		e.Unlink.File.FileFields.UID = uint32(v)
		return nil

	case "unlink.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.User"}
		}
		e.Unlink.File.FileFields.User = str

		return nil

	case "unlink.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.SyscallEvent.Retval"}
		}
		e.Unlink.SyscallEvent.Retval = int64(v)
		return nil

	case "utimes.file.container_path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.ContainerPath"}
		}
		e.Utimes.File.ContainerPath = str

		return nil

	case "utimes.file.filesystem":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.Filesytem"}
		}
		e.Utimes.File.Filesytem = str

		return nil

	case "utimes.file.gid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.GID"}
		}
		e.Utimes.File.FileFields.GID = uint32(v)
		return nil

	case "utimes.file.group":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.Group"}
		}
		e.Utimes.File.FileFields.Group = str

		return nil

	case "utimes.file.in_upper_layer":

		var ok bool
		if e.Utimes.File.InUpperLayer, ok = value.(bool); !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.InUpperLayer"}
		}
		return nil

	case "utimes.file.inode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.Inode"}
		}
		e.Utimes.File.FileFields.Inode = uint64(v)
		return nil

	case "utimes.file.mode":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.Mode"}
		}
		e.Utimes.File.FileFields.Mode = uint16(v)
		return nil

	case "utimes.file.mount_id":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.MountID"}
		}
		e.Utimes.File.FileFields.MountID = uint32(v)
		return nil

	case "utimes.file.name":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.BasenameStr"}
		}
		e.Utimes.File.BasenameStr = str

		return nil

	case "utimes.file.path":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.PathnameStr"}
		}
		e.Utimes.File.PathnameStr = str

		return nil

	case "utimes.file.uid":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.UID"}
		}
		e.Utimes.File.FileFields.UID = uint32(v)
		return nil

	case "utimes.file.user":

		var ok bool
		str, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.User"}
		}
		e.Utimes.File.FileFields.User = str

		return nil

	case "utimes.retval":

		var ok bool
		v, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.SyscallEvent.Retval"}
		}
		e.Utimes.SyscallEvent.Retval = int64(v)
		return nil

	}

	return &eval.ErrFieldNotFound{Field: field}
}
