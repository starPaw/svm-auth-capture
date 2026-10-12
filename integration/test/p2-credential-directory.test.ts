import {expect,test} from 'vitest';
import {credentialDirectory} from '../operators/p2-presigner-stop.ts';
const actual='/run/credentials/capture402-e2e-p2-57070b79-1663-4cff-b39b-12c5c765a625.service';
test('accepts actual systemd UUID unit credential directory including .service',()=>expect(credentialDirectory(actual)).toBe(actual));
test.each([undefined,'',actual.replace('.service',''),actual+'.service',actual+'/../keys',actual.replace('capture402-e2e-p2-','other-'),actual.replace('57070b79','ABCDEF00'),actual.replace('57070b79','57070'),actual.replace('/run/credentials/','/tmp/'),actual.replace('.service','/'),actual+'\n'])('rejects foreign or malformed credential path %j',value=>expect(()=>credentialDirectory(value)).toThrow());
