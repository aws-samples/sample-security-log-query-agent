// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/** Runtime and architecture shared by every Python function in this app. */
export const PYTHON_RUNTIME = lambda.Runtime.PYTHON_3_12;
export const PYTHON_ARCHITECTURE = lambda.Architecture.X86_64;

// pip target that matches PYTHON_RUNTIME on PYTHON_ARCHITECTURE, so a local
// install on macOS or Windows still produces Linux wheels for Lambda.
// Local build output that must never ship in the function package.
const EXCLUDED_SOURCE = ['__pycache__', '*.pyc'];

const PIP_PLATFORM_ARGS = [
  '--platform', 'manylinux2014_x86_64',
  '--implementation', 'cp',
  '--python-version', '3.12',
  '--only-binary=:all:',
];

/**
 * Packages a Lambda source directory together with the dependencies in its
 * requirements.txt. `cdk synth` installs them into the asset, so the deployed
 * function contains them. Local pip is tried first; if it is unavailable or
 * fails, CDK falls back to the Lambda Python build image in Docker.
 */
export function pythonCode(sourceDir: string): lambda.Code {
  return lambda.Code.fromAsset(sourceDir, {
    assetHashType: cdk.AssetHashType.OUTPUT,
    exclude: EXCLUDED_SOURCE,
    bundling: {
      image: PYTHON_RUNTIME.bundlingImage,
      platform: 'linux/amd64',
      command: [
        'bash', '-c',
        'pip install --no-cache-dir -r requirements.txt -t /asset-output && cp -au . /asset-output',
      ],
      local: {
        tryBundle(outputDir: string): boolean {
          const pip = spawnSync(
            'python3',
            [
              '-m', 'pip', 'install',
              '--quiet', '--disable-pip-version-check', '--no-compile',
              ...PIP_PLATFORM_ARGS,
              '--target', outputDir,
              '-r', path.join(sourceDir, 'requirements.txt'),
            ],
            { stdio: 'inherit' },
          );
          if (pip.error || pip.status !== 0) {
            return false;
          }
          for (const entry of fs.readdirSync(sourceDir)) {
            if (entry === '__pycache__' || entry.endsWith('.pyc')) {
              continue;
            }
            fs.cpSync(path.join(sourceDir, entry), path.join(outputDir, entry), { recursive: true });
          }
          return true;
        },
      },
    },
  });
}
