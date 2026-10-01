import { imageType } from './image.js';

export async function vulnerablePreview(value) {
  let url;
  try { url = new URL(value); } catch { throw Object.assign(new Error('URL을 확인하세요.'), { status: 400 }); }
  if (!['http:', 'https:'].includes(url.protocol)) throw Object.assign(new Error('HTTP 또는 HTTPS 주소를 입력하세요.'), { status: 400 });
  // 의도적인 SSRF: 목적지 도메인/IP와 리다이렉트를 검사하지 않습니다.
  // 내부 서비스 요청을 서버가 대신 수행합니다. EC2에서 접근 가능한 주소가 대상입니다.
  const response = await fetch(url, { signal: AbortSignal.timeout(8000) });
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 5 * 1024 * 1024) throw Object.assign(new Error('응답은 최대 5MB입니다.'), { status: 413 });
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  const result = { status: response.status, contentType: response.headers.get('content-type') || '', fetchedUrl: response.url };
  try { return { ...result, image: `data:${imageType(bytes)};base64,${bytes.toString('base64')}` }; }
  catch { return { ...result, image: null, text: bytes.toString('utf8').slice(0, 16000) }; }
}
