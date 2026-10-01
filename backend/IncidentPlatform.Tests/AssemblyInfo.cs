using Xunit;

// Serilog's bootstrap logger (Log.Logger) is a single static instance shared
// across the whole test process. Program.cs's top-level statements — and
// therefore Log.CloseAndFlush() in its finally block — run once per
// TestApiFactory creation. If two test classes run in
// parallel (xUnit's default), one factory can close the shared logger while
// another is still starting up on a different thread, causing spurious
// startup failures that have nothing to do with the tests themselves.
//
// Disabling test parallelization serializes test execution, so only one
// Program.cs Main() invocation is ever in flight at a time.
[assembly: CollectionBehavior(DisableTestParallelization = true)]