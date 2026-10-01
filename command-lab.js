import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const failure = (status, message) => Object.assign(new Error(message), { status });
// ponytail: 단일 EC2 실습용. 한 번에 하나의 요청만 실행합니다.
let running = false;
export async function runCommandLab(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 200 || value.includes('\0')) throw failure(400, '입력값은 1~200자의 문자열이어야 합니다.');
  if (running) throw failure(429, '다른 실습이 실행 중입니다. 잠시 후 다시 시도하세요.');
  running = true;
  // 의도적인 OS 명령어 인젝션: 입력을 셸 명령에 그대로 붙입니다.
  // EC2에서 웹앱을 실행한 OS 계정의 권한으로 실행됩니다.
  const command = `printf '%s\\n' ${value}`;
  const task = execute('/bin/sh', ['-c', command], {
    timeout: 8000, killSignal: 'SIGKILL', maxBuffer: 32 * 1024,
    encoding: 'utf8', shell: false, detached: true
  });
  try {
    const { stdout, stderr } = await task;
    return { stdout, stderr, exitCode: 0 };
  } catch (error) {
    if (error.killed || error.signal || error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') throw failure(408, '실행 시간 또는 출력 크기 제한에 도달했습니다.');
    if (typeof error.code === 'number') return { stdout: error.stdout || '', stderr: error.stderr || '', exitCode: error.code };
    throw failure(500, 'OS 명령을 실행하지 못했습니다.');
  } finally {
    if (task.child?.pid) {
      try { process.kill(-task.child.pid, 'SIGKILL'); }
      catch (error) { if (error.code !== 'ESRCH') console.error('command_group_cleanup_failed'); }
    }
    running = false;
  }
}
