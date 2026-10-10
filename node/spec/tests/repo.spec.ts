import { it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';
import { AddressInfo } from 'node:net';
import * as repo from '../../lib/repo';
import { replaceVersion } from '../../lib/retire';
import { Repository } from '../../lib/types';
import { options } from '../options';

it('rejects malformed local and remote repositories with source context', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-json-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'broken.json');
  fs.writeFileSync(file, '{');

  await assert.rejects(repo.loadrepositoryFromFile(file, options), (error) => String(error).includes(file));

  const server = http.createServer((req, res) => res.end('{'));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = 'http://127.0.0.1:' + (server.address() as AddressInfo).port + '/broken.json';

  await assert.rejects(repo.loadrepository(url, options), (error) => String(error).includes(url));
});

const repositoryWithFilename = (filename: string) =>
  ({ example: { vulnerabilities: [], extractors: { filename: [filename] } } }) as unknown as Repository;

it('reports extractors without a version capture group instead of throwing', () => {
  for (const filename of ['example-§§version§§\\.js', '(?:example)-§§version§§\\.js', '(example)-(§§version§§)\\.js']) {
    for (const replacer of [undefined, replaceVersion]) {
      const repository = replacer
        ? JSON.parse(replacer(JSON.stringify(repositoryWithFilename(filename))))
        : repositoryWithFilename(filename);
      const result = repo.validateRepository(repository, replacer);

      assert.equal(result.success, false, filename);
      assert.deepEqual(
        result.error!.issues.map((issue) => [issue.path.join('.'), issue.message.split(':')[0]]),
        [['example.extractors.filename.0', 'Regex must contain (§§version§§) as first capture group']],
        filename,
      );
    }
  }
});

it('does not validate the extractors of the "dont check" entry', () => {
  const repository = {
    'dont check': { vulnerabilities: [], extractors: { uri: ['^https?://example.com/analytics.js'] } },
  } as unknown as Repository;
  assert.equal(repo.validateRepository(repository).success, true);
  assert.equal(repo.validateRepository(repositoryWithFilename('example\\.js')).success, false);
});

it('formats validation errors with one line per issue and its path', () => {
  const result = repo.validateRepository(repositoryWithFilename('example\\.js'));
  assert.equal(
    repo.formatValidationError(result.error!),
    '✖ Regex must contain (§§version§§): example\\.js\n  → at example.extractors.filename[0]',
  );
});
