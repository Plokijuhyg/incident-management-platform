using System.Collections.Concurrent;
namespace IncidentPlatform.Api.Services;

// Lets the controller stop an in-flight orchestration run: the worker registers a linked
// CancellationTokenSource while a run executes, and a cancel request trips it so the current
// model call / tool poll aborts promptly. In-process only (worker and controller share it); a
// run orphaned by an API restart is reset to Failed on worker startup instead.
public sealed class OrchestrationCancellation
{
 private readonly ConcurrentDictionary<string,CancellationTokenSource> _runs=new();
 public CancellationTokenSource Register(string id,CancellationToken linked)
 {
  var cts=CancellationTokenSource.CreateLinkedTokenSource(linked);
  _runs[id]=cts;
  return cts;
 }
 public bool TryCancel(string id)
 {
  if(!_runs.TryGetValue(id,out var cts))return false;
  try{cts.Cancel();}catch(ObjectDisposedException){}
  return true;
 }
 public void Unregister(string id){if(_runs.TryRemove(id,out var cts))cts.Dispose();}
}
