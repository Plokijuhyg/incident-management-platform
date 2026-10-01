// Real Chromium rendering and navigation with deterministic API fixtures.
// Run after npm run build. No production account or database is modified.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = resolve(root, 'dist/incident-platform/browser');
assert(existsSync(join(dist, 'index.html')), 'Run npm run build first.');
const binary = [
  process.env['BROWSER_PATH'],
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/chromium',
  '/usr/bin/google-chrome',
].find((path) => path && existsSync(path));
assert(binary, 'Set BROWSER_PATH to a Chromium browser executable.');
const profile = resolve(root, `dist/browser-check-profile-${Date.now()}`);
mkdirSync(profile, { recursive: true });
const mime = {
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.html': 'text/html',
  '.ico': 'image/x-icon',
};
const server = createServer((request, response) => {
  let path = resolve(dist, '.' + new URL(request.url, 'http://localhost').pathname);
  if (!path.startsWith(dist + sep) && path !== dist) {
    response.writeHead(403).end();
    return;
  }
  if (!existsSync(path) || !extname(path)) path = join(dist, 'index.html');
  response.setHeader('Content-Type', mime[extname(path)] ?? 'application/octet-stream');
  response.end(readFileSync(path));
});
await new Promise((done) => server.listen(0, '127.0.0.1', done));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = spawn(
  binary,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    'about:blank',
  ],
  { windowsHide: true, stdio: 'ignore' },
);
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
async function until(check, message) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await check()) return;
    await sleep(100);
  }
  throw new Error(message);
}
let socket;
try {
  await until(() => existsSync(join(profile, 'DevToolsActivePort')), 'Browser did not start.');
  const port = readFileSync(join(profile, 'DevToolsActivePort'), 'utf8').split('\n')[0].trim();
  const tabs = await fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json());
  socket = new WebSocket(tabs.find((tab) => tab.type === 'page').webSocketDebuggerUrl);
  await new Promise((done, reject) => {
    socket.addEventListener('open', done, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  let sequence = 0;
  const pending = new Map();
  const runtimeErrors = [];
  const requests = [];
  function cdp(method, params = {}) {
    return new Promise((done, reject) => {
      const id = ++sequence;
      const timeout = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`Timed out: ${method}`));
      }, 10000);
      pending.set(id, { done, reject, timeout });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }
  let detail = {
    id: 42,
    recommendedActions: [{alertId:11,ruleId:'SIGMA-fixture',text:'Review authentication evidence before considering containment.'}],
    incidentNumber: 'INC-2026-000042',
    title: 'Suspicious sign-in activity',
    description: 'Investigate repeated sign-in attempts against the finance application.',
    severity: 3,
    priority: 2,
    status: 0,
    category: 2,
    source: 5,
    createdById: 7,
    createdByName: 'Browser test analyst',
    assignedToId: null,
    assignedToName: null,
    occurredAt: null,
    detectedAt: null,
    createdAt: '2026-09-24T08:00:00',
    updatedAt: '2026-09-24T08:00:00',
    triagedAt: null,
    containedAt: null,
    resolvedAt: null,
    closedAt: null,
    resolutionSummary: null,
    version: 0,
  };
  let adminSession = false;
  let assessmentConnected = false;
  const assessmentId='11111111-2222-4333-8444-555555555555';
  const assessmentFixture={id:assessmentId,targetName:'Approved lab',targetIp:'192.168.207.129',profile:'selected-tools',status:'Completed',requestedAt:'2026-10-01T00:00:00Z',error:null,evidenceSha256:'abc',observationsJson:JSON.stringify([{kind:'Service',port:80,service:'http'}]),rawResponse:'{}',analysisJson:null};
  let analysisCalls=0;
  let releaseAnalysis;

  let comments = [];
  let alert = {
    id: 11,
    title: 'Lab service exposure',
    description: 'Review the lab evidence.',
    source: 6,
    severity: 'High',
    status: 0,
    detectedAt: '2026-09-25T10:00:00Z',
    rawPayload: '{"tool":"nmap","evidence":"fixture"}',
    incidentId: null,
  };
  const indicator = {
    id: 12,
    value: '192.168.207.129',
    type: 0,
    confidence: 1,
    isMalicious: null,
    sightingCount: 1,
    incidents: [],
  };
  const asset = {
    id: 13,
    name: 'Metasploitable lab',
    ipAddress: '192.168.207.129',
    assetType: 1,
    criticality: 1,
    isActive: true,
    incidents: [],
  };
  const technique = {
    id: 14,
    techniqueId: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    isSubTechnique: false,
    description: 'Service enumeration',
    incidents: [],
  };
  let evidenceFiles = [];
  let managedUser = {
    id: 8,
    email: 'colleague@example.com',
    fullName: 'Browser colleague',
    jobTitle: 'SOC analyst',
    roles: ['SOC_ANALYST'],
    isActive: true,
    createdAt: '2026-09-24T08:00:00',
    lastLoginAt: null,
  };
  const page = (items) => ({
    items,
    page: 1,
    pageSize: 25,
    totalCount: items.length,
    totalPages: 1,
    hasNextPage: false,
    hasPreviousPage: false,
  });
  socket.addEventListener('message', async (event) => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const item = pending.get(message.id);
      if (item) {
        clearTimeout(item.timeout);
        pending.delete(message.id);
        message.error ? item.reject(new Error(message.error.message)) : item.done(message.result);
      }
      return;
    }
    if (message.method === 'Runtime.exceptionThrown')
      runtimeErrors.push(message.params.exceptionDetails.text);
    if (message.method !== 'Fetch.requestPaused') return;
    try {
      const { request, requestId } = message.params;
      const path = new URL(request.url).pathname;
      requests.push({
        path,
        method: request.method,
        headers: request.headers,
        body: request.postData,
      });
      let code = 200;
      let body;
      if (path === '/api/auth/refresh') {
        code = 401;
        body = {};
      } else if (path === '/api/auth/login') {
        adminSession = JSON.parse(request.postData).email === 'admin@example.com';
        body = {
          accessToken: 'browser-test-token',
          expiresIn: 900,
          user: {
            id: 7,
            fullName: 'Browser test analyst',
            email: 'browser@example.com',
            roles: adminSession ? ['ADMIN'] : ['SOC_ANALYST'],
          },
        };
      } else if (path === '/api/auth/logout') {
        code = 204;
        body = null;
      } else {
        assert.equal(
          request.headers['Authorization'],
          'Bearer browser-test-token',
          'API request must carry the JWT.',
        );
        const payload =
          request.postData && request.headers['Content-Type']?.includes('application/json')
            ? JSON.parse(request.postData)
            : {};
        if (path.startsWith('/api/dashboard/')) {
          const endpoint = path.split('/').pop();
          const params = new URL(request.url).searchParams;
          const groups = {
            'incidents-by-severity': [
              { label: 'Critical', count: 3 },
              { label: 'High', count: 8 },
              { label: 'Medium', count: 7 },
            ],
            'incidents-by-status': [
              { label: 'Investigating', count: 10 },
              { label: 'Resolved', count: 8 },
            ],
            'incidents-by-category': [
              { label: 'Phishing', count: 8 },
              { label: 'UnauthorizedAccess', count: 10 },
            ],
            'top-ioc-types': [
              { label: 'IPAddress', count: 5 },
              { label: 'Domain', count: 3 },
            ],
          };
          if (endpoint === 'summary')
            body = {
              totalIncidents: 18,
              openIncidents: 10,
              criticalOpenIncidents: 3,
              unassignedIncidents: 2,
              myOpenIncidents: 4,
              newAlerts: 6,
              incidentsCreatedToday: 2,
            };
          else if (endpoint === 'metrics')
            body = {
              meanTimeToDetectMinutes: 12.5,
              meanTimeToContainMinutes: 45,
              meanTimeToResolveMinutes: null,
              sampleSize: 18,
              periodDays: +params.get('periodDays'),
              detectionSampleSize: 10,
              containmentSampleSize: 8,
              resolutionSampleSize: 0,
            };
          else if (endpoint === 'incidents-over-time')
            body = Array.from({ length: +params.get('days') }, (_, index) => ({
              start: new Date(
                Date.UTC(2026, 8, 24 - +params.get('days') + index + 1),
              ).toISOString(),
              count: index % 5,
            }));
          else if (endpoint === 'top-mitre-techniques')
            body = [{ techniqueId: 'T1566', name: 'Phishing', count: 8 }];
          else {
            assert(endpoint in groups, `Unhandled dashboard API: ${path}`);
            body = groups[endpoint];
          }
        } else if (path === '/api/roles')
          body = ['ADMIN', 'SECURITY_MANAGER', 'SOC_ANALYST'].map((name, id) => ({
            id,
            name,
            description: null,
          }));
        else if (path === '/api/users/assignable')
          body = [{ id: 8, fullName: managedUser.fullName }];
        else if (path === '/api/users' && request.method === 'POST') {
          managedUser = { ...managedUser, ...payload };
          delete managedUser.password;
          body = managedUser;
          code = 201;
        } else if (path === '/api/users') body = page([managedUser]);
        else if (path === '/api/users/8/deactivate') {
          managedUser.isActive = false;
          body = null;
          code = 204;
        } else if (path === '/api/users/8/roles') {
          managedUser.roles = payload.roles;
          body = managedUser;
        } else if (path === '/api/users/8') {
          if (request.method === 'PUT') managedUser = { ...managedUser, ...payload };
          body = managedUser;
        } else if (/\/evidence\/5\/download$/.test(path)) body = 'browser log content';
        else if (/\/evidence\/5$/.test(path) && request.method === 'DELETE') {
          evidenceFiles = [];
          code = 204;
          body = null;
        } else if (/\/evidence$/.test(path)) {
          if (request.method === 'POST') {
            assert(request.headers['Content-Type'].includes('multipart/form-data; boundary='));
            evidenceFiles = [
              {
                id: 5,
                originalFileName: 'browser.log',
                contentType: 'text/plain',
                sizeBytes: 19,
                sha256: 'a'.repeat(64),
                evidenceType: 7,
                description: 'Authentication events',
                uploadedByName: 'Browser admin',
                uploadedAt: '2026-09-24T08:00:00',
              },
            ];
            body = evidenceFiles[0];
          } else body = evidenceFiles;
        } else if (/\/incidents\/\d+\/(assign|status|close)$/.test(path)) {
          if (path.endsWith('/assign'))
            detail = {
              ...detail,
              assignedToId: payload.assignedToId,
              assignedToName: managedUser.fullName,
            };
          else if (path.endsWith('/status')) detail = { ...detail, status: payload.status };
          else
            detail = {
              ...detail,
              status: 7,
              resolutionSummary: payload.resolutionSummary,
              closedAt: '2026-09-24T09:00:00',
            };
          detail.version++;
          body = detail;
        } else if (path === '/api/incidents' && request.method === 'POST') {
          detail = {
            ...detail,
            ...JSON.parse(request.postData),
            id: 43,
            incidentNumber: 'INC-2026-000043',
          };
          body = detail;
          code = 201;
        } else if (path === '/api/incidents')
          body = {
            items: [detail],
            page: 1,
            pageSize: 25,
            totalCount: 1,
            totalPages: 1,
            hasNextPage: false,
            hasPreviousPage: false,
          };
        else if (/^\/api\/incidents\/\d+$/.test(path)) {
          if (request.method === 'PUT') {
            assert.equal(payload.version, detail.version);
            detail = { ...detail, ...payload, version: detail.version + 1 };
          }
          body = detail;
        } else if (path === '/api/alerts') {
          if (request.method === 'POST') alert = { ...alert, ...payload };
          body = request.method === 'POST' ? alert : page([alert]);
        } else if (path === '/api/alerts/11') body = alert;
        else if (path === '/api/alerts/11/promote') {
          alert = { ...alert, status: 3, incidentId: detail.id };
          body = detail;
        } else if (path === '/api/alerts/11/false-positive') {
          alert = { ...alert, status: 2 };
          body = alert;
        } else if (path === '/api/iocs') body = page([indicator]);
        else if (path === '/api/iocs/12' || path === '/api/iocs/lookup') body = indicator;
        else if (path === '/api/assets') body = page([asset]);
        else if (path === '/api/assets/13') body = asset;
        else if (path === '/api/notifications/status') body={enabled:false,configured:false,minimumSeverity:'High',missing:['Notifications:Smtp:Host'],counts:[]};
        else if (/^\/api\/(alerts|incidents)\/\d+\/enrichment$/.test(path)) {
          const report={type:'domain',value:'example.com',status:'Available',malicious:2,total:70,categories:['Browser fixture'],checkedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString(),message:'Existing reputation report; zero detections is not proof of safety.'};
          if(request.method==='POST'){const input=JSON.parse(request.postData);assert.equal(input.confirmed,true);assert.equal(input.value,'example.com');body=report;}
          else body={configured:true,candidates:[{type:'domain',value:'example.com'}],reports:[]};
        }
        else if (path === '/api/mitre/tactics') body = ['Discovery'];
        else if (path === '/api/mitre/techniques') body = [technique];
        else if (path === '/api/mitre/techniques/T1046') body = technique;
        else if (path.startsWith('/api/audit-logs/entity/Incident/')) body=page([{id:1,action:'INCIDENT_CREATED',actorEmail:'admin@example.com',occurredAt:'2026-09-25T10:00:00Z',details:'Fixture audit changes'}]);
        else if (path === '/api/audit-logs')
          body = page([
            {
              id: 1,
              action: 'ALERT_CREATED',
              entityType: 'Alert',
              entityId: '11',
              outcome: 0,
              actorEmail: 'admin@example.com',
              ipAddress: '127.0.0.1',
              occurredAt: '2026-09-25T10:00:00Z',
              details: 'Recorded lab evidence',
            },
          ]);
        else if (path === '/api/soc/overview') body = {
          observedAt:new Date().toISOString(),start:new Date(Date.now()-86400000).toISOString(),bucketMinutes:5,total:1,
          categories:[{label:'Malware',count:1,high:1,medium:0}],topHosts:[{id:31,name:'Fixture SOC host',ip:'192.0.2.10',count:1,high:1}],topIncidents:[{title:'Fixture investigation',count:1}],
          timeline:[{bucket:20,severity:2,count:1}],latest:[{id:42,incidentNumber:'INC-FIXTURE',title:'Fixture investigation',severity:2,status:0,category:0,createdAt:new Date().toISOString(),owner:'Fixture owner'}]
        };
        else if (path === '/api/soc/attacks') body = {
          techniques:[technique,{id:1,techniqueId:'T1059',name:'Command and Scripting Interpreter',tactic:'Execution',isSubTechnique:false}],counts:[{id:1,count:1}],devices:[{id:31,name:'Fixture SOC host',tactic:'Execution',count:1}]
        };
        else if (path === '/api/soc/techniques/1/incidents') body = [{id:42,incidentNumber:'INC-FIXTURE',title:'Fixture investigation',severity:2,status:0}];
        else if (path === '/api/soc/tasks') body = {total:1,items:[{id:1,incidentId:42,incidentNumber:'INC-FIXTURE',actionType:10,description:'Restore lab service',targetValue:'Fixture host',status:0,result:null,owner:'Fixture owner'}]};
        else if (path === '/api/soc/analytics') body = {observedAt:new Date().toISOString(),start:new Date(Date.now()-3600000).toISOString(),width:1,total:1,series:[{index:30,count:1}],items:[{id:1,receivedAt:new Date().toISOString(),machine:'Fixture SOC host',provider:'Fixture provider',channel:'Application',eventId:1000,level:4,message:'Fixture raw message'}],hasMore:false};
        else if (path === '/api/detection-rules') body = {total:1,page:1,items:[{id:1,externalRuleId:'10000000-0000-4000-8000-000000000001',title:'Sigma review fixture',severity:'High',referenceTag:'attack.t1110',enabled:false,updatedAt:'2026-09-27T10:00:00Z',unsupportedReason:null,definition:{logsource:{product:'windows',service:'security'},detection:{selection:{EventID:4625},condition:'selection'},tags:['attack.t1110'],sourceFile:'fixture.yml',sourceSha256:'fixture',description:'Failed login fixture',falsepositives:['Authorized lab activity']}}]};
        else if (path === '/api/detection-rules/1/enabled' && request.method === 'PUT') {
          const review=JSON.parse(request.postData);
          assert(!review.enabled || review.confirmed,'Sigma rule enabled without review confirmation');
          body={id:1,enabled:review.enabled,updatedAt:'2026-09-27T11:00:00Z'};
        }
        else if (path === '/api/automation/rules') body = {
          catalogRevision: '2026-09-26.1', lastCycleAt: new Date().toISOString(), error: null,
          owners: [{id: 7, fullName: 'Policy owner'}], rules: [{
            policy: {id:'WIN-DEFENDER-DETECTION',mode:'Observe',version:1,correlationMinutes:60,ownerId:null,effectiveFrom:new Date().toISOString()},
            definition: {name:'Defender threat detection',channel:'Defender/Operational',provider:'Microsoft-Windows-Windows Defender',eventId:1116,canAutoPromote:true,falsePositives:'Authorized lab samples require review.',reference:'https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus',mappings:[]},counts:[]
          }] };
        else if (path === '/api/automation/rules/WIN-DEFENDER-DETECTION' && request.method === 'PUT') body = {...JSON.parse(request.postData),version:2,effectiveFrom:new Date().toISOString()};
        else if (path === '/api/automation/decisions') body = {items:[],hasMore:false};
        else if (path === '/api/automation/coverage') body = {
          scope:'Local test fixture only',mappings:[],gaps:['Organizational scope requires assessment.'],
          evidence:{enabled:true,retentionDays:7,lastCycleAt:new Date().toISOString(),storedEvents:1234,decisions:0,channels:[]},
          benchmark:{platform:'Windows 11',profile:'Level 1 proposed',status:'Not assessed',version:null,reference:'https://www.cisecurity.org/benchmark/microsoft_windows_desktop',reason:'Configuration evidence is required.'}
        };
        else if (path === '/api/assessments/capabilities')
          body = assessmentConnected ? {
            connected:true, message:'Live MCP fixture',profiles:[],manifestId:'fixture',tools:[
              {name:'nikto_scan',category:'Web',tier:'intrusive',available:true,description:'Bounded web checks',reason:''},
              {name:'graphql_scanner',category:'API',tier:'unclassified',available:false,description:'GraphQL',reason:'No reviewed adapter'}
            ]
          } : {connected:false,message:'Not configured. Laptop 2 is not available yet.',profiles:[],tools:[]};
        else if (path === '/api/assessments/targets') body = [{id:'lab',name:'Approved lab',ip:'192.168.207.129'}];
        else if (path === '/api/assessments/analysis/status') body={configured:true,model:'llama3.1:8b',promptVersion:'defensive-brief-v2'};
        else if (path === '/api/assessments/'+assessmentId+'/analysis') {
          assert.equal(request.method,'POST');analysisCalls++;
          await new Promise(resolve=>{releaseAnalysis=resolve;});
          body={status:'Completed',model:'llama3.1:8b',evidenceSha256:'abc',inputSha256:'def',promptVersion:'defensive-brief-v2',generatedAt:new Date().toISOString(),text:'1. Vulnerability Summary - Fixture observation <script>unsafe()</script>\n2. Attack Surface - HTTP\n3. Detection Guidance - Inspect access logs\n4. Mitigation Steps - Review configuration\n5. Severity Justification - No CVSS provided',error:null,includedObservations:1,totalObservations:1,inputTruncated:false,outputTruncated:false};
          assessmentFixture.analysisJson=JSON.stringify(body);
        }
        else if (path === '/api/assessments/'+assessmentId) body=assessmentFixture;
        else if (path === '/api/assessments') body = [assessmentFixture];
        else if (path === '/api/windows-events/activity')
          body = {
            observedAt: new Date().toISOString(), enabled: true, windowsSupported: true,
            error: null, lastCycleAt: new Date().toISOString(), lastReceivedAt: new Date().toISOString(),
            retentionDays: 7, storedEvents: 1234, eventsLastMinute: 12,
            enabledChannels: 3, readableChannels: 2, blockedChannels: 1, backlogChannels: 0,
            timeline: Array.from({ length: 30 }, (_, i) => ({ start: new Date(Date.now()-(29-i)*60000).toISOString(), count: i % 5 })),
            topChannels: [{ label: 'Application', count: 12 }],
            latest: [{ id: 1, channel: 'Application', provider: 'Live fixture provider', eventId: 1000, level: 4, receivedAt: new Date().toISOString(), timeCreated: new Date().toISOString(), alertId: null }],
          };
        else if (path === '/api/windows-events/status')
          body = {
            enabled: true,
            pollSeconds: 2,
            retentionDays: 7,
            machine: 'Fixture host',
            lastCycleAt: '2026-09-25T10:00:00Z',
            error: null,
            windowsSupported: true,
            storedEvents: 1,
            channels: [
              {
                id: 1,
                channel: 'Application',
                enabled: true,
                startedAt: '2026-09-25T09:00:00Z',
                lastCheckedAt: '2026-09-25T10:00:00Z',
                error: null,
                hasBacklog: false,
              },
            ],
          };
        else if (path === '/api/windows-events')
          body = {
            items: [
              {
                id: 1,
                machine: 'Fixture host',
                channel: 'Application',
                provider: 'Fixture provider',
                recordId: 42,
                eventId: 1000,
                level: 2,
                timeCreated: '2026-09-25T10:00:00Z',
                receivedAt: '2026-09-25T10:00:01Z',
                alertId: null,
              },
            ],
            hasMore: false,
          };
        else if (path === '/api/windows-events/1')
          body = {
            id: 1,
            machine: 'Fixture host',
            channel: 'Application',
            provider: 'Fixture provider',
            recordId: 42,
            eventId: 1000,
            level: 2,
            timeCreated: '2026-09-25T10:00:00Z',
            message: '<script>fixture</script>',
            rawXml: '<Event>isolated browser fixture</Event>',
          };
        else if (path === '/api/lab/connections')
          body = { hexStrikeUrl: 'http://127.0.0.1:8888', ollamaUrl: 'http://127.0.0.1:11434' };
        else if (path === '/api/lab/connections/hexstrike/check')
          body = {
            service: 'hexstrike',
            url: 'http://127.0.0.1:8888',
            reachable: true,
            message: 'Service responded successfully.',
            checkedAt: '2026-09-25T10:00:00Z',
          };
        else if (/\/incidents\/\d+\/comments$/.test(path)) {
          if (request.method === 'POST')
            comments.push({
              id: 1,
              ...payload,
              authorName: 'Browser admin',
              createdAt: '2026-09-25T10:00:00Z',
            });
          body = request.method === 'POST' ? comments.at(-1) : comments;
        } else if (
          /\/incidents\/\d+\/(timeline|response-actions|iocs|assets|mitre-techniques)$/.test(path)
        )
          body = [];
        else throw new Error(`Unhandled API: ${request.method} ${path}`);
      }
      await cdp('Fetch.fulfillRequest', {
        requestId,
        responseCode: code,
        responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
        body: Buffer.from(body === null ? '' : JSON.stringify(body)).toString('base64'),
      });
    } catch (error) {
      runtimeErrors.push(error.message);
    }
  });
  const downloadPath = resolve(profile, 'downloads');
  mkdirSync(downloadPath, { recursive: true });
  await cdp('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath });
  await cdp('Page.enable');
  await cdp('Runtime.enable');
  await cdp('Fetch.enable', { patterns: [{ urlPattern: '*/api/*' }] });
  const evaluate = async (expression) =>
    (await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })).result
      .value;
  const clickButton = (label) =>
    evaluate(
      `Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === ${JSON.stringify(label)}).click()`,
    );
  const fill = (values) =>
    evaluate(
      `for (const [id, value] of ${JSON.stringify(values)}) { const input = document.getElementById(id); input.value = value; input.dispatchEvent(new Event('input', { bubbles: true })); }`,
    );
  const submitForm = (index = 0) =>
    evaluate(`document.querySelectorAll('form')[${index}].requestSubmit()`);
  const selectIndex = (id, index) =>
    evaluate(
      `{ const el = document.getElementById(${JSON.stringify(id)}); el.selectedIndex = ${index}; el.dispatchEvent(new Event('change', { bubbles: true })); }`,
    );
  const textHas = (text) => evaluate(`document.body.innerText.includes(${JSON.stringify(text)})`);
  async function screenshot(name) {
    const shot = await cdp('Page.captureScreenshot', { format: 'png' });
    writeFileSync(resolve(root, `dist/${name}.png`), Buffer.from(shot.data, 'base64'));
  }
  await cdp('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 1000,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await cdp('Page.navigate', { url: `${origin}/incidents/42` });
  await until(() => textHas('Sign in to your workspace'), 'Login did not render.');
  await screenshot('browser-login');
  await evaluate(
    `for (const [id, value] of [['email','browser@example.com'],['password','test-password']]) { const input = document.getElementById(id); input.value = value; input.dispatchEvent(new Event('input', { bubbles: true })); } document.querySelector('form').requestSubmit();`,
  );
  await until(
    () => textHas('Incident overview'),
    'Return navigation did not open the requested incident.',
  );
  await evaluate(`document.querySelector('.back-link').click()`);
  await until(() => textHas('Incident register'), 'Incident register did not render.');
  await until(() => textHas('Suspicious sign-in activity'), 'Incident data did not render.');
  await screenshot('browser-incidents');
  await evaluate(`document.querySelector('a[href="/incidents/new"]').click()`);
  await until(() => textHas('A useful first report'), 'Create page did not render.');
  await cdp('Emulation.setDeviceMetricsOverride', {
    width: 390,
    height: 844,
    deviceScaleFactor: 1,
    mobile: true,
  });
  await screenshot('browser-create-mobile');
  assert(
    await evaluate('document.documentElement.scrollWidth <= window.innerWidth'),
    'Mobile page overflows horizontally.',
  );
  await evaluate(
    `for (const [id, value] of [['title','Browser smoke incident'],['description','A deterministic browser-test report.']]) { const input = document.getElementById(id); input.value = value; input.dispatchEvent(new Event('input', { bubbles: true })); } document.querySelector('form').requestSubmit();`,
  );
  await until(
    () =>
      evaluate(
        `location.pathname === '/incidents/43' && document.body.innerText.includes('Incident overview')`,
      ),
    'Create did not navigate to the persisted incident.',
  );
  const created = requests.find((r) => r.path === '/api/incidents' && r.method === 'POST');
  assert(created);
  const payload = JSON.parse(created.body);
  assert.equal(payload.severity, 1);
  assert.equal(payload.source, 5);
  assert.equal(payload.occurredAt, null);
  await evaluate(
    `Array.from(document.querySelectorAll('button')).find(button => button.textContent.includes('Sign out')).click()`,
  );
  await until(() => textHas('Sign in to your workspace'), 'Logout did not return to login.');
  // Administrator workflows, with deterministic fixtures and no database writes.
  await fill([
    ['email', 'admin@example.com'],
    ['password', 'test-password'],
  ]);
  await submitForm();
  await until(() => textHas('Incident register'), 'Admin login failed.');
  await evaluate(`document.querySelector('a.incident-link').click()`);
  await until(() => textHas('Edit incident'), 'Admin actions missing.');
  await clickButton('Edit incident');
  await until(() => evaluate(`!!document.getElementById('edit-title')`), 'Edit form missing.');
  await fill([['edit-title', 'Updated browser incident']]);
  await submitForm();
  await until(() => textHas('Incident updated.'), 'Incident update failed.');
  await clickButton('Assign owner');
  await until(
    () => evaluate(`document.querySelectorAll('#assignee option').length === 2`),
    'Assignees missing.',
  );
  await selectIndex('assignee', 1);
  await submitForm();
  await until(() => textHas('Owner assigned.'), 'Assignment failed.');
  await clickButton('Change status');
  await until(
    () => evaluate(`!!document.getElementById('incident-status')`),
    'Status form missing.',
  );
  await selectIndex('incident-status', 2);
  await submitForm();
  await until(() => textHas('Status updated.'), 'Status update failed.');
  await evaluate(
    `{ const transfer = new DataTransfer(); transfer.items.add(new File(['browser log content'], 'browser.log', { type: 'text/plain' })); const input = document.getElementById('evidence-file'); input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true })); }`,
  );
  await fill([['evidence-description', 'Authentication events']]);
  await clickButton('Upload evidence');
  await until(() => textHas('browser.log'), 'Evidence upload failed.');
  await evaluate(`document.querySelector('app-evidence').scrollIntoView({ block: 'start' })`);
  await screenshot('browser-evidence-mobile');
  assert(
    await evaluate('document.documentElement.scrollWidth <= window.innerWidth'),
    'Evidence page overflows on mobile.',
  );
  await clickButton('Download');
  await until(() => existsSync(join(downloadPath, 'browser.log')), 'Evidence download failed.');
  await clickButton('Delete');
  await until(() => textHas('Confirm delete'), 'Evidence delete confirmation missing.');
  assert.equal(evidenceFiles.length, 1);
  await clickButton('Confirm delete');
  await until(() => textHas('Evidence deleted.'), 'Evidence deletion failed.');
  await clickButton('Close incident');
  await until(() => evaluate(`!!document.getElementById('resolution')`), 'Close form missing.');
  await fill([['resolution', 'Access restored and monitoring enabled.']]);
  await submitForm();
  await until(() => textHas('Incident closed.'), 'Incident closure failed.');
  await evaluate(`document.querySelector('a[href="/dashboard"]').click()`);
  await until(() => textHas('Mean time to detect'), 'Dashboard did not load.');
  await evaluate('window.scrollTo(0, 0)');
  await screenshot('browser-dashboard-mobile');
  assert(
    await evaluate(
      `document.querySelector('.account').getBoundingClientRect().bottom <= document.querySelector('.topbar').getBoundingClientRect().bottom`,
    ),
    'Mobile account controls escape the top bar',
  );
  assert(
    await evaluate('document.documentElement.scrollWidth <= window.innerWidth'),
    'Dashboard overflows on mobile.',
  );
  await selectIndex('dashboard-period', 0);
  await until(() => textHas('last 7 days'), 'Dashboard period did not change.');
  await cdp('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 1000,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await screenshot('browser-dashboard');
  assert.equal(
    await evaluate(`document.querySelectorAll('.incident-trend .trend-point').length`),
    7,
    'The line chart must render the seven API buckets',
  );
  await evaluate(`document.querySelector('.incident-trend').scrollIntoView({block:'center'})`);
  await screenshot('browser-dashboard-trend');
  await evaluate(`document.querySelector('a[href="/users"]').click()`);
  await until(() => textHas('Browser colleague'), 'User directory did not load.');
  await evaluate(`document.querySelector('a[href="/users/new"]').click()`);
  await until(() => textHas('New account'), 'New user form missing.');
  await fill([
    ['user-name', 'Browser new colleague'],
    ['user-email', 'new@example.com'],
    ['new-password', 'SafeTest123'],
  ]);
  await submitForm();
  await until(() => textHas('Manage user'), 'User creation failed.');
  await until(() => evaluate(`!!document.getElementById('user-name')`), 'User editor missing.');
  await fill([['job-title', 'Incident responder']]);
  await submitForm();
  await until(() => textHas('Profile updated.'), 'User profile update failed.');
  await evaluate(`document.querySelectorAll('input[type=checkbox]')[1].click()`);
  await submitForm(1);
  await until(() => textHas('Roles updated.'), 'Role update failed.');
  assert(managedUser.roles.includes('SECURITY_MANAGER'));
  await screenshot('browser-user');
  await clickButton('Deactivate user');
  await until(() => textHas('Confirm deactivation'), 'Deactivation confirmation missing.');
  assert.equal(managedUser.isActive, true);
  await clickButton('Confirm deactivation');
  await until(() => textHas('Account deactivated.'), 'Account deactivation failed.');
  const go = async (path, text) => {
    await evaluate(`document.querySelector('nav a[href="${path}"]').click()`);
    await until(() => textHas(text), `${path} did not render.`);
  };
  await go('/alerts', 'Lab service exposure');
  await screenshot('browser-alerts');
  await evaluate(`document.querySelector('a[href="/alerts/11"]').click()`);
  await until(() => textHas('Promote to incident'), 'Alert detail missing');
  await clickButton('Load indicators & saved reports');
  await until(()=>evaluate(`!!document.querySelector('.intel-select select')`),'Intel candidates missing');
  await evaluate(`const select=document.querySelector('.intel-select select');select.value='0';select.dispatchEvent(new Event('change',{bubbles:true}));`);
  assert(await evaluate(`Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Enrich selected indicator').disabled`),'Unconfirmed enrichment enabled');
  await evaluate(`document.querySelector('.intel-confirm input').click()`);
  await clickButton('Enrich selected indicator');
  await until(()=>textHas('2 / 70 malicious verdicts'),'Enrichment result missing');

  await clickButton('Promote to incident');
  await until(() => textHas('Incident overview'), 'Promotion failed');
  await until(() => textHas('Suggestion only. Human review is required'), 'Response guidance label missing');
  await clickButton('Open audit history');
  await until(()=>textHas('INCIDENT_CREATED'),'Scoped audit history missing');
  await clickButton('Open investigation workspace');
  await until(
    () => evaluate(`!!document.getElementById('investigation-comments-body')`),
    'Investigation form missing',
  );
  await fill([['investigation-comments-body', 'Validated the lab service evidence.']]);
  await clickButton('Add to investigation');
  await until(() => textHas('Validated the lab service evidence.'), 'Comment was not recorded');
  for (const label of ['Timeline', 'Response actions', 'Indicators', 'Assets', 'MITRE mappings']) {
    await evaluate(
      `Array.from(document.querySelectorAll('app-investigation button')).find(b=>b.textContent.trim()===${JSON.stringify(label)}).click()`,
    );
    await until(
      () =>
        evaluate(
          `!document.querySelector('app-investigation [role="status"]') || !document.querySelector('app-investigation [role="status"]').textContent.includes('Loading')`,
        ),
      'Investigation tab stuck',
    );
  }
  await go('/iocs', '192.168.207.129');
  await evaluate(`document.querySelector('a[href="/iocs/12"]').click()`);
  await until(() => textHas('Edit indicator'), 'Indicator detail missing');
  assert(
    await evaluate(`document.getElementById('field-isMalicious').selectedIndex === 0`),
    'Null verdict became malicious/benign',
  );
  await go('/assets', 'Metasploitable lab');
  await evaluate(`document.querySelector('a[href="/assets/13"]').click()`);
  await until(() => textHas('Edit asset'), 'Asset detail missing');
  await go('/attack-matrix', 'Network Service Discovery');
  assert(await evaluate(`document.querySelectorAll('.coverage-matrix th').length === 2 && document.querySelectorAll('.coverage-cell.has-incidents').length === 1`), 'Coverage matrix or evidence colors missing');
  await evaluate(`document.querySelector('.coverage-cell.has-incidents').click()`);
  await until(()=>textHas('INC-FIXTURE'), 'Coverage cell did not open linked incidents');
  assert(await evaluate(`!!document.querySelector('dialog[open]')`),'Technique details must be a popup');
  await screenshot('browser-attack-coverage');
  await evaluate(`document.querySelector('dialog[open] header button').click()`);
  await evaluate(`document.querySelector('a[href="/attack-matrix/T1046"]').click()`);
  await until(() => textHas('Service enumeration'), 'MITRE detail missing');
  await go('/audit', 'ALERT_CREATED');
  await go('/lab', 'Lab connections');
  await until(() => textHas('127.0.0.1:8888'), 'Lab settings missing');
  await clickButton('Test connection');
  await until(() => textHas('Connected'), 'Connection result missing');
  await clickButton('Check assessment gateway');
  await until(() => textHas('Gateway or MCP unavailable'), 'Raw health incorrectly implied MCP readiness');
  assessmentConnected = true;
  await clickButton('Check assessment gateway');
  await until(() => textHas('Live MCP connected'), 'MCP readiness check missing');
  assessmentConnected = false;
  await clickButton('Check email configuration');
  await until(() => textHas('Notifications:Smtp:Host'), 'Email configuration status missing');
  await screenshot('browser-lab');
  await go('/windows-events', 'Windows Events');
  await until(() => textHas('Fixture provider'), 'Windows events missing');
  await clickButton('Pause live view');
  await evaluate(`window.__eventScroll=window.scrollY;const b=Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Inspect event');b.focus({preventScroll:true});window.__eventTrigger=b;`);
  await clickButton('Inspect event');
  await until(() => textHas('<script>fixture</script>'), 'Event message missing');
  assert(await evaluate(`!!document.querySelector('dialog[open]') && document.body.style.overflow==='hidden' && Math.abs(window.scrollY-window.__eventScroll)<3`),'Event details moved the page instead of opening a modal');
  await clickButton('Original Windows XML');
  await until(() => textHas('isolated browser fixture'), 'Event XML popup missing');
  assert(await evaluate(`document.querySelectorAll('dialog[open]').length===2`),'Nested evidence popup missing');
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await until(()=>evaluate(`document.querySelectorAll('dialog[open]').length===1`),'Escape did not close only the top popup');
  assert(await evaluate(`document.body.style.overflow==='hidden'`),'Nested close unlocked the background');

  assert(
    await evaluate(`!document.querySelector('.event-detail script')`),
    'Event text became executable markup',
  );
  await evaluate(`document.querySelector('dialog[open] header button').click()`);
  await until(()=>evaluate(`!document.querySelector('dialog[open]') && document.activeElement===window.__eventTrigger && document.body.style.overflow!== 'hidden'`),'Closing event did not restore focus and scrolling');
  await screenshot('browser-windows-events');
  await go('/assessments', 'Security Assessments');
  await until(
    () => textHas('Gateway unavailable'),
    'Disconnected gateway status missing',
  );
  assert(
    await evaluate(
      `Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Start assessment').disabled`,
    ),
    'Unconfigured assessment can start',
  );
  assessmentConnected = true;
  await clickButton('Check gateway');
  await until(() => textHas('Gateway connected'), 'Live manifest missing');
  await selectIndex('assessment-target', 1);
  await evaluate(`Array.from(document.querySelectorAll('legend label')).find(e=>e.textContent.trim()==='Web').querySelector('input').click()`);
  await until(() => textHas('nikto_scan'), 'Manifest tool checkbox missing');
  await evaluate(`document.querySelector('.scan-tool input').click()`);
  await until(() => textHas('I confirm the selected'), 'Intrusive confirmation missing');
  assert(await evaluate(`Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Start assessment').disabled`), 'Unconfirmed scope can start');
  assert(await evaluate(`Array.from(document.querySelectorAll('.assessment-builder input[type=checkbox]')).every(e=>{const r=e.getBoundingClientRect();return r.width<=20 && r.height<=20;})`), 'Assessment checkboxes stretched');
  await screenshot('browser-assessments');
  await cdp('Emulation.setDeviceMetricsOverride', {width:390,height:844,deviceScaleFactor:1,mobile:true});
  await until(() => evaluate(`getComputedStyle(document.querySelector('.assessment-builder')).gridTemplateColumns.split(' ').length===1`), 'Mobile assessment layout did not collapse');
  assert(await evaluate(`document.querySelector('.assessment-builder').getBoundingClientRect().right<=window.innerWidth`), 'Mobile assessment overflows viewport');
  await screenshot('browser-assessments-mobile');
  await clickButton('Inspect assessment');
  await until(()=>textHas('Ollama defensive brief'),'Analysis panel missing');
  assert.equal(analysisCalls,0,'Opening evidence triggered inference automatically');
  await until(()=>evaluate(`!Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Analyze results with Ollama').disabled`),'Analysis button unavailable');
  await clickButton('Analyze results with Ollama');
  await until(()=>Promise.resolve(!!releaseAnalysis),'Analysis request did not start');
  await clickButton('Minimize');
  assert(await evaluate(`!document.querySelector('dialog[open]') && document.body.style.overflow!=='hidden'`),'Minimize did not release the page');
  await until(()=>textHas('Ollama is analyzing...'),'Background task status missing');
  await clickButton('Restore analysis');
  await until(()=>evaluate(`!!document.querySelector('dialog[open]')`),'Restore did not reopen evidence');
  await evaluate(`document.querySelector('dialog[open] [aria-label="Close details"]').click()`);
  await clickButton('Restore analysis');
  await until(()=>evaluate(`!!document.querySelector('dialog[open]')`),'Second restore failed');
  await evaluate(`document.querySelector('dialog[open]').dispatchEvent(new MouseEvent('click',{bubbles:true,clientX:0,clientY:0}))`);
  assert(await evaluate(`!document.querySelector('dialog[open]')`),'Backdrop did not close popup');
  await evaluate(`document.querySelector('a[href="/dashboard"]').click()`);
  await until(()=>evaluate(`location.pathname==='/dashboard'`),'SPA navigation failed');
  assert.equal(analysisCalls,1,'Minimize or navigation duplicated inference');
  releaseAnalysis();
  await until(()=>textHas('Analysis ready'),'Analysis did not finish in background');
  await clickButton('Restore analysis');
  await until(()=>textHas('5. Severity Justification'),'Five-section brief missing');
  assert.equal(analysisCalls,1);
  assert(await evaluate(`!document.querySelector('.analysis-text script')`),'Model output was rendered as executable HTML');
  await screenshot('browser-ollama-analysis-mobile');
  await evaluate(`document.querySelector('dialog[open] header button').click()`);
  await clickButton('Inspect assessment');
  await until(()=>textHas('5. Severity Justification'),'Saved analysis was not restored');
  assert.equal(analysisCalls,1,'Reopening evidence unexpectedly generated another report');
  await evaluate(`document.querySelector('dialog[open] header button').click()`);

  await cdp('Emulation.setDeviceMetricsOverride', {width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  await go('/overview', 'Incident overview');
  await until(() => textHas('Fixture SOC host'), 'SOC overview not loaded');
  await screenshot('browser-soc-overview');
  await go('/attack-matrix', 'MITRE ATT&CK coverage');
  await until(() => textHas('Command and Scripting Interpreter'), 'MITRE matrix missing');
  await evaluate(`Array.from(document.querySelectorAll('.link-button')).find(b=>b.textContent.trim()==='T1059').click()`);
  await until(() => textHas('INC-FIXTURE'), 'Technique incident drill-down missing');
  await screenshot('browser-soc-mitre');
  await go('/analytics', 'Event analytics');
  await until(() => textHas('Fixture raw message'), 'Analytics rows missing');
  await clickButton('Raw event');
  await until(() => textHas('<script>fixture</script>'), 'Raw event evidence missing');
  await until(() => evaluate(`!!document.querySelector('dialog[open]')?.contains(document.activeElement)`), 'Raw event popup did not receive focus');
  await screenshot('browser-soc-analytics');
  await go('/tasks', 'Response tasks');
  await until(() => textHas('Restore lab service'), 'Response tasks missing');
  await screenshot('browser-soc-tasks');
  await go('/automation', 'Automation & coverage');
  await until(() => textHas('Defender threat detection'), 'Automation rules missing');
  assert(await textHas('Not assessed'), 'Benchmark must not claim compliance');
  await evaluate(`document.getElementById('WIN-DEFENDER-DETECTION-mode').value='AutoPromote'; document.getElementById('WIN-DEFENDER-DETECTION-mode').dispatchEvent(new Event('change',{bubbles:true}));`);
  await evaluate(`const e=document.getElementById('WIN-DEFENDER-DETECTION-owner');e.selectedIndex=1;e.dispatchEvent(new Event('change',{bubbles:true}));`);
  await clickButton('Save policy');
  await until(() => textHas('Policy saved.'), 'Automation policy not saved');
  await clickButton('Load rules');
  await until(() => textHas('Sigma review fixture'), 'Imported Sigma rules missing');
  await evaluate(`document.querySelector('app-imported-rules .popup-trigger').click()`);
  await until(() => textHas('Authorized lab activity'), 'Rule false-positive context missing');
  assert(await evaluate(`Array.from(document.querySelectorAll('app-imported-rules button')).find(b=>b.textContent.includes('Enable reviewed rule')).disabled`),'Sigma enable did not require review');
  await evaluate(`document.querySelector('app-imported-rules input[type=checkbox]').click()`);
  await clickButton('Enable reviewed rule');
  await until(() => textHas('Rule enabled for newly ingested events.'), 'Reviewed Sigma activation failed');
  await clickButton('Disable detection');
  await until(() => textHas('Rule disabled. Existing evidence is retained.'), 'Sigma disable failed');
  await screenshot('browser-automation');
  await go('/account', 'Current password');
  await clickButton('Sign out');
  await until(() => textHas('Sign in to your workspace'), 'Admin logout failed.');
  // A manually entered admin route must also be denied to a signed-in analyst.
  await cdp('Page.navigate', { url: `${origin}/users` });
  await until(() => textHas('Sign in to your workspace'), 'Users login redirect failed.');
  await fill([
    ['email', 'browser@example.com'],
    ['password', 'test-password'],
  ]);
  await submitForm();
  await until(
    () => evaluate(`location.pathname === '/forbidden'`),
    'Analyst was not blocked from Users.',
  );
  assert(
    await evaluate(`!document.querySelector('nav a[href="/users"]')`),
    'Analyst sees admin navigation.',
  );
  await clickButton('Sign out');
  await until(() => textHas('Sign in to your workspace'), 'Final logout failed.');
  assert.deepEqual(runtimeErrors, []);
  console.log(
    'Browser smoke passed: login, incidents create/edit/assign/status/close, evidence upload/download/delete, dashboard, user create/profile/roles/deactivate, alerts promotion, investigation comments and tabs, IOC/asset/MITRE details, audit, lab connection check, account, mobile layouts, JWT and analyst route restrictions.',
  );
  console.log('Screenshots saved under frontend/dist/browser-*.png');
  await cdp('Browser.close').catch(() => {});
} finally {
  socket?.close();
  browser.kill();
  await new Promise((done) => server.close(done));
}
