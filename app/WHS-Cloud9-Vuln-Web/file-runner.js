import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const execute = promisify(execFile);
const fail = (status, message) => Object.assign(new Error(message), { status });
// ponytail: 단일 서버에서 실행 요청 1개만 허용합니다. 전역 작업 큐/실행 이력은 없습니다.
let running = false;
export async function runUploadedFile(file) {
  const extension = path.extname(file.name).toLowerCase();
  const runtime = ['.js', '.mjs', '.cjs'].includes(extension) ? process.execPath : extension === '.py' ? 'python3' : extension === '.sh' ? '/bin/sh' : null;
  if (!runtime) throw fail(400, '지원하지 않는 실행 파일입니다.');
  if (running) throw fail(429, '다른 파일을 실행 중입니다. 잠시 후 다시 시도하세요.');
  running = true;
  let folder, task;
  const started = Date.now();
  try {
    folder = await mkdtemp(path.join(tmpdir(), 'whs-file-run-'));
    const script = path.join(folder, `upload${extension}`);
    await writeFile(script, file.bytes, { mode: 0o600 });
    // 의도적인 파일 업로드 → 서버 코드 실행 실습. 사용자 입력으로 실행 프로그램/인자는 바꾸지 않습니다.
    // 임시 폴더는 보안 격리가 아닙니다. 코드에는 웹앱 OS 계정의 권한이 있습니다.
    task = execute(runtime, [script], { cwd: folder, timeout: 8000, maxBuffer: 32 * 1024, killSignal: 'SIGKILL', detached: true, shell: false,
      env: { PATH: process.env.PATH || '/usr/bin:/bin', LANG: 'C.UTF-8', HOME: folder, TMPDIR: folder } });
    const { stdout, stderr } = await task;
    return { name: file.name, stdout, stderr, exitCode: 0, durationMs: Date.now() - started };
  } catch (error) {
    if (error.code === 'ENOENT') throw fail(400, '실행 프로그램이 없습니다. Python 파일은 EC2에 python3가 필요합니다.');
    if (error.killed || error.signal || error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') throw fail(408, '실행 시간(8초) 또는 출력(32KB) 제한에 도달했습니다.');
    if (typeof error.code === 'number') return { name: file.name, stdout: error.stdout || '', stderr: error.stderr || '', exitCode: error.code, durationMs: Date.now() - started };
    throw error;
  } finally {
    try {
      if (task?.child?.pid) {
        try { process.kill(-task.child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') console.error('file_run_process_cleanup_failed'); }
      }
      if (folder) await rm(folder, { recursive: true, force: true });
    } finally { running = false; }
  }
}
