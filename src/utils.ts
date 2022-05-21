import Https from 'https';
import axios, { AxiosRequestConfig } from 'axios';
import fssync from 'fs';
import { arrayBuffer } from 'stream/consumers';

export const Axios = axios.create({
  timeout: 3000,
  httpsAgent: new Https.Agent({
  rejectUnauthorized: !getBooleanEnvVar('ALLOW_INVALID_CERTIFICATES', false)
})});



// eslint-disable-next-line @typescript-eslint/no-empty-function
export const noop = () => {};



export function sleep(ms: number): Promise<void> {
  return new Promise<void>( (resolve) => {
    setTimeout( () => resolve(), ms )
  });
}



export function deepCopy<T>(o: T): T {
  // taken from https://jsperf.com/deep-copy-vs-json-stringify-json-parse/5

  if (typeof o !== 'object') {
    return o;
  }
  if (!o) {
    return o;
  }

  if (Array.isArray(o)) {
    const newO = o.map( item => deepCopy(item) );
    return newO as unknown as T;
  }

  const newO: Record<string, unknown> = {};
  Object.entries((o as Record<string, unknown>))
    .forEach(
      ([key, value]) => newO[key] = deepCopy(value)
    );
  return newO as T;
}


export function sortNumber(a: number, b: number): number {
  return b - a;
}


export function getStringEnvVar(key: string, defaultValue: string): string;
export function getStringEnvVar(key: string): string | undefined;
export function getStringEnvVar(key: string, defaultValue?: string): string | undefined {
  return process.env[key] ?? defaultValue;
}



export  function getBooleanEnvVar(key: string, defaultValue: boolean): boolean {
  const envValue = process.env[key]?.toLowerCase();
  return envValue === 'true'
    ? true
    : envValue === 'false'
      ? false
      : defaultValue;
}


export  function getNumberEnvVar(key: string, defaultValue: number): number {
  const envValue = process.env[key];
  if (!envValue?.match(/^\d+$/)) {
    return defaultValue;
  }
  return parseFloat(envValue);
}



export async function downloadFile(url: string, filename: string, axiosOptions: AxiosRequestConfig): Promise<void> {
  // fetch the file and write it to disk
  axiosOptions.responseType = 'stream';
  const writer = fssync.createWriteStream(filename);
  const response = await Axios.get(url, axiosOptions);
  return new Promise<void>((resolve, reject) => {
    // from https://stackoverflow.com/questions/55374755/node-js-axios-download-file-stream-and-writefile
    response.data.pipe(writer);
    let error: any;
    writer.on('error', err => {
      error = err;
      writer.close();
      reject(err);
    });
    writer.on('close', () => {
      if (!error) {
        resolve();
      }
      // no need to call reject() here, as it will have been called in the 'error' stream;
    });
  });
}



export function dos2unix(str: string): string {
  return str.replace(/\r\n/g, '\n');
}
