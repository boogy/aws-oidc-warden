package logevent

// AuditMarshalFailure is emitted when marshaling an audit record fails
// (Error).
var AuditMarshalFailure = newEvent("audit.marshal.failure")

// AuditWriteFailure is emitted when writing an audit record fails (Error).
var AuditWriteFailure = newEvent("audit.write.failure")

// AuditBufferFailure is emitted when buffering an audit record fails
// (Error).
var AuditBufferFailure = newEvent("audit.buffer.failure")

// AuditFlushSuccess is emitted when the audit buffer flushes successfully
// (Debug).
var AuditFlushSuccess = newEvent("audit.flush.success")

// AuditFlushFailure is emitted when flushing the audit buffer fails (Error).
var AuditFlushFailure = newEvent("audit.flush.failure")

// AuditClientInit is emitted when the audit sink client initializes (Info).
var AuditClientInit = newEvent("audit.client.init")

// AuditClientInitFailure is emitted when initializing the audit sink client
// fails (Error).
var AuditClientInitFailure = newEvent("audit.client.init.failure")
