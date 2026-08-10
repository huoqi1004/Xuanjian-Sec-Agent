const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGVfaWQiOjEsImlhdCI6MTc4NjMyOTM2OSwiZXhwIjoxNzg2NDE1NzY5fQ.ApO9G_zsq99gTzFvTWmwWYzPYF7wcXQO_eSvR2zbOaU';

async function test() {
  const results = [];

  // 1. Metrics 未认证应返回 401
  const r1 = await fetch('http://localhost:3000/metrics');
  results.push({ name: 'Metrics 无认证', pass: r1.status === 401, actual: r1.status });

  // 2. Metrics 有认证应返回 200
  const r2 = await fetch('http://localhost:3000/metrics', { headers: { 'Authorization': 'Bearer ' + token } });
  results.push({ name: 'Metrics 有认证', pass: r2.status === 200, actual: r2.status });

  // 3. Djpp-data-check 未认证应返回 401
  const r3 = await fetch('http://localhost:3000/api/djpp-data-check');
  results.push({ name: 'Djpp-data-check 无认证', pass: r3.status === 401, actual: r3.status });

  // 4. Djpp-data-check 有认证应返回 200
  const r4 = await fetch('http://localhost:3000/api/djpp-data-check', { headers: { 'Authorization': 'Bearer ' + token } });
  results.push({ name: 'Djpp-data-check 有认证', pass: r4.status === 200, actual: r4.status });

  // 5. AI Chat 正常
  const r5 = await fetch('http://localhost:3000/api/ai/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify({ message: '你好', conversation_id: 'sec-test' })
  });
  const j5 = await r5.json();
  results.push({ name: 'AI 对话', pass: r5.status === 200 && j5.data?.content, actual: r5.status });

  // 6. 安全头检查
  const r6 = await fetch('http://localhost:3000/api/health');
  results.push({ name: 'HSTS 头', pass: !!r6.headers.get('strict-transport-security'), actual: r6.headers.get('strict-transport-security')?.substring(0, 30) });
  results.push({ name: 'X-Content-Type-Options', pass: r6.headers.get('x-content-type-options') === 'nosniff', actual: r6.headers.get('x-content-type-options') });
  results.push({ name: 'X-Frame-Options', pass: !!r6.headers.get('x-frame-options'), actual: r6.headers.get('x-frame-options') });

  let pass = 0;
  results.forEach(t => {
    const icon = t.pass ? '✅' : '❌';
    const detail = t.pass ? '' : ` (expected OK, got: ${t.actual})`;
    console.log(icon, t.name + detail);
    if (t.pass) pass++;
  });
  console.log(`\n共 ${pass}/${results.length} 项通过`);
  if (pass < results.length) process.exit(1);
}

test().catch(e => { console.error(e); process.exit(1); });
