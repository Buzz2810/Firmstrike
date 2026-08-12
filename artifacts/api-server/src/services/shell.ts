import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function runCommand(
  command: string,
  args: string[],
  options?: {
    cwd?: string;
    timeoutMs?: number;
    maxBuffer?: number;
  },
): Promise<{ stdout: string; stderr: string }> {
  const { stdout, stderr } = await execFileAsync(command, args, {
    cwd: options?.cwd,
    timeout: options?.timeoutMs ?? 120_000,
    maxBuffer: options?.maxBuffer ?? 20 * 1024 * 1024,
    windowsHide: true,
  });

  return {
    stdout: stdout.toString(),
    stderr: stderr.toString(),
  };
}

export async function commandExists(
  command: string,
): Promise<boolean> {
  try {
    const checker =
      process.platform === "win32"
        ? "where.exe"
        : "which";

    await execFileAsync(
      checker,
      [command],
      {
        timeout: 5_000,
        windowsHide: true,
      },
    );

    return true;
  } catch {
    return false;
  }
}