import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';

// SECRET_ID가 설정된 경우 EC2 IAM 역할로 Secrets Manager에서 비밀값을 읽습니다.
export async function loadSecrets(env = process.env) {
  const secretId = env.SECRETS_MANAGER_SECRET_ID;
  if (!secretId) return;

  const client = new SecretsManagerClient({ region: env.AWS_REGION || 'ap-northeast-2' });
  const result = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
  if (!result.SecretString) throw new Error('Secrets Manager 값은 JSON 문자열이어야 합니다.');

  let secret;
  try {
    secret = JSON.parse(result.SecretString);
  } catch {
    throw new Error('Secrets Manager 값이 올바른 JSON이 아닙니다.');
  }

  for (const key of ['SESSION_SECRET', 'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD']) {
    if (typeof secret[key] !== 'string' || !secret[key]) {
      throw new Error(`Secrets Manager JSON에 ${key} 값이 필요합니다.`);
    }
    env[key] = secret[key];
  }
}
