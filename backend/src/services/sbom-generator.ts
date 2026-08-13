import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { db, sbomReportsTable, sbomComponentsTable } from "@workspace/db";
import { firmwareExtractPath, reportPath } from "../lib/paths.js";
import { eq } from "drizzle-orm";

export type SbomComponent = {
  name: string;
  version: string;
  type: string;
  path: string;
  source: string;
};

export type SbomReportPaths = {
  cyclonedxPath: string;
  spdxPath: string;
  csvPath: string;
};

function normalizeComponentName(raw: string): string {
  return raw.replace(/[^\w.\-]+/g, " ").trim().replace(/\s+/g, " ");
}

function detectLibraryVersion(fileName: string, content: string): string {
  const versionPatterns = [
    /([\d]+\.[\d]+\.[\d]+(?:-[a-z0-9.]+)?)/i,
    /version[:=]\s*([\d]+\.[\d]+(?:\.[\d]+)?)/i,
  ];

  for (const pattern of versionPatterns) {
    const match = fileName.match(pattern) ?? content.match(pattern);
    if (match?.[1]) {
      return match[1];
    }
  }

  return "unknown";
}

async function getFileStrings(filePath: string): Promise<string> {
  try {
    const raw = await fs.readFile(filePath);
    if (raw.includes(0)) return "";
    return raw.toString("utf8");
  } catch {
    return "";
  }
}

async function discoverPackages(extractPath: string): Promise<SbomComponent[]> {
  const components: SbomComponent[] = [];
  const queue = [extractPath];

  while (queue.length > 0) {
    const current = queue.pop();
    if (!current) continue;
    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const full = path.join(current, entry.name);
      const rel = `/${path.relative(extractPath, full).replace(/\\/g, "/")}`;

      if (entry.isDirectory()) {
        queue.push(full);
        continue;
      }

      const lower = entry.name.toLowerCase();
      if (lower === "package.json" || lower === "requirements.txt" || lower === "setup.py" || lower === "pyproject.toml") {
        const content = await getFileStrings(full);
        const version = detectLibraryVersion(entry.name, content);
        components.push({
          name: normalizeComponentName(entry.name.replace(/\.(json|txt|py|toml)$/i, "")),
          version,
          type: "package-manifest",
          path: rel,
          source: "filesystem",
        });
        continue;
      }

      if (lower.endsWith(".so") || lower.endsWith(".dll") || lower.endsWith(".dylib")) {
        const content = await getFileStrings(full);
        const version = detectLibraryVersion(entry.name, content);
        components.push({
          name: normalizeComponentName(entry.name.replace(/\.(so|dll|dylib)$/i, "")),
          version,
          type: "shared-library",
          path: rel,
          source: "filesystem",
        });
        continue;
      }

      if (lower.endsWith(".bin") || lower.endsWith(".elf") || lower.includes("busybox") || lower.includes("openssl") || lower.includes("dropbear")) {
        const content = await getFileStrings(full);
        const version = detectLibraryVersion(entry.name, content);
        const componentName = normalizeComponentName(entry.name.replace(/\.(bin|elf)$/i, ""));
        if (componentName) {
          components.push({
            name: componentName,
            version,
            type: "binary",
            path: rel,
            source: "firmware-image",
          });
        }
      }
    }
  }

  return components;
}

function writeCycloneDx(components: SbomComponent[], outputPath: string): Promise<void> {
  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.4",
    version: 1,
    components: components.map((component) => ({
      type: component.type === "shared-library" ? "library" : "application",
      name: component.name,
      version: component.version,
      description: `Detected from ${component.source}`,
      hashes: [{ alg: "SHA-256", content: createHash("sha256").update(component.name + component.path).digest("hex") }],
      properties: [
        { name: "sbom:source", value: component.source },
        { name: "sbom:path", value: component.path },
      ],
    })),
  };

  return fs.writeFile(outputPath, JSON.stringify(bom, null, 2), "utf8");
}

function writeSpdx(components: SbomComponent[], outputPath: string): Promise<void> {
  const sbom = {
    SPDXID: "SPDXRef-DOCUMENT",
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    name: "FirmStrike SBOM",
    documentNamespace: `http://firmstrike.local/sbom/${Date.now()}`,
    creationInfo: {
      creators: ["Tool: FirmStrike SBOM Generator"],
      created: new Date().toISOString(),
    },
    packages: components.map((component, index) => ({
      SPDXID: `SPDXRef-Package-${index + 1}`,
      name: component.name,
      versionInfo: component.version,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      supplier: "NOASSERTION",
      externalRefs: [{
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: `pkg:${component.source}/${component.name}@${component.version}`,
      }],
      description: `Detected in firmware at ${component.path}`,
    })),
  };

  return fs.writeFile(outputPath, JSON.stringify(sbom, null, 2), "utf8");
}

function writeCsv(components: SbomComponent[], outputPath: string): Promise<void> {
  const rows = ["name,version,type,path,source"];
  for (const component of components) {
    rows.push(
      [component.name, component.version, component.type, component.path, component.source]
        .map((value) => `"${String(value).replace(/"/g, '""')}"`)
        .join(","),
    );
  }
  return fs.writeFile(outputPath, rows.join("\n"), "utf8");
}

export async function generateSbomReport(firmwareId: number, extractPath: string): Promise<SbomReportPaths> {
  const components = await discoverPackages(extractPath);
  const reportBase = reportPath(firmwareId).replace(/\.txt$/, "");
  const cyclonedxPath = `${reportBase}-sbom-cyclonedx.json`;
  const spdxPath = `${reportBase}-sbom-spdx.json`;
  const csvPath = `${reportBase}-sbom.csv`;

  await writeCycloneDx(components, cyclonedxPath);
  await writeSpdx(components, spdxPath);
  await writeCsv(components, csvPath);

  await db.insert(sbomComponentsTable).values(
    components.map((component) => ({
      firmwareId,
      name: component.name,
      version: component.version,
      type: component.type,
      path: component.path,
      source: component.source,
    })),
  );

  await db.insert(sbomReportsTable).values({
    firmwareId,
    cyclonedxPath,
    spdxPath,
    csvPath,
    componentCount: components.length,
  }).onConflictDoUpdate({
    target: sbomReportsTable.firmwareId,
    set: {
      cyclonedxPath,
      spdxPath,
      csvPath,
      componentCount: components.length,
      generatedAt: new Date(),
    },
  });

  return { cyclonedxPath, spdxPath, csvPath };
}

export async function getSbomReport(firmwareId: number) {
  const [report] = await db.select().from(sbomReportsTable).where(eq(sbomReportsTable.firmwareId, firmwareId));
  if (!report) return null;
  const components = await db.select().from(sbomComponentsTable).where(eq(sbomComponentsTable.firmwareId, firmwareId));
  return { report, components };
}
