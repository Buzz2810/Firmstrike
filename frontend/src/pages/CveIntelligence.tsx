import { useState, useMemo } from "react";
import { useParams, Link } from "wouter";
import {
  useGetCveMatches, getGetCveMatchesQueryKey,
  useGetCvssScores,  getGetCvssScoresQueryKey,
} from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Bug, ChevronLeft, ExternalLink, Search as SearchIcon,
  ShieldAlert, TriangleAlert, ShieldCheck, ArrowUpDown, ChevronsUpDown,
  CalendarDays, Layers, Info,
} from "lucide-react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTooltip, ResponsiveContainer, Cell, LabelList,
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
} from "recharts";

// ─── Types ───────────────────────────────────────────────────────────────────

type SortKey  = "severity" | "cvssScore" | "cveId" | "publishedDate" | "component";
type SortDir  = "asc" | "desc";

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function severityColor(s: string) {
  switch (s?.toLowerCase()) {
    case "critical": return "hsl(var(--destructive))";
    case "high":     return "#f97316";
    case "medium":   return "#eab308";
    case "low":      return "#22c55e";
    default:         return "hsl(var(--primary))";
  }
}

function scoreTextClass(score: number) {
  if (score >= 9.0) return "text-destructive drop-shadow-[0_0_8px_rgba(239,68,68,0.7)]";
  if (score >= 7.0) return "text-orange-500 drop-shadow-[0_0_6px_rgba(249,115,22,0.5)]";
  if (score >= 4.0) return "text-yellow-500";
  return "text-green-500";
}

function scoreLabel(score: number) {
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  return "Low";
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "bg-destructive/10 text-destructive border-destructive/30",
    high:     "bg-orange-500/10 text-orange-500 border-orange-500/30",
    medium:   "bg-yellow-500/10 text-yellow-500 border-yellow-500/30",
    low:      "bg-green-500/10  text-green-500  border-green-500/30",
  };
  return (
    <Badge
      variant="outline"
      className={`uppercase text-[10px] font-mono ${map[severity?.toLowerCase()] ?? "bg-muted text-muted-foreground border-border"}`}
    >
      {severity}
    </Badge>
  );
}

// ─── CVE Row ─────────────────────────────────────────────────────────────────

function CveRow({ cve, idx }: { cve: any; idx: number }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <motion.tr
        key={cve.id}
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: Math.min(idx * 0.025, 0.5) }}
        className={`border-border/20 hover:bg-muted/5 transition-colors cursor-pointer ${
          cve.severity === "critical" ? "bg-destructive/5" : ""
        }`}
        onClick={() => setExpanded(e => !e)}
      >
        {/* CVE ID */}
        <TableCell className="font-mono text-sm font-bold py-3">
          <div className="flex items-center gap-2">
            <a
              href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
              target="_blank"
              rel="noreferrer"
              onClick={e => e.stopPropagation()}
              className="text-primary hover:underline flex items-center gap-1 whitespace-nowrap"
            >
              {cve.cveId}
              <ExternalLink className="w-3 h-3 opacity-50 shrink-0" />
            </a>
          </div>
        </TableCell>

        {/* Severity */}
        <TableCell className="py-3"><SeverityBadge severity={cve.severity} /></TableCell>

        {/* CVSS Score — visual bar */}
        <TableCell className="py-3 w-28">
          <div className="flex flex-col gap-1">
            <span className={`font-mono text-sm font-bold ${scoreTextClass(cve.cvssScore)}`}>
              {cve.cvssScore?.toFixed(1) ?? "N/A"}
            </span>
            <div className="h-1 w-full rounded bg-muted/40 overflow-hidden">
              <div
                className="h-full rounded transition-all"
                style={{
                  width: `${Math.min(100, (cve.cvssScore / 10) * 100)}%`,
                  backgroundColor: severityColor(cve.severity),
                }}
              />
            </div>
          </div>
        </TableCell>

        {/* Affected Component */}
        <TableCell className="font-mono text-xs text-muted-foreground py-3 max-w-[120px] truncate">
          {cve.affectedComponent}
        </TableCell>

        {/* Description — truncated, expands on row click */}
        <TableCell className="text-xs text-muted-foreground py-3 max-w-xs">
          <span className={expanded ? "" : "line-clamp-1"}>
            {cve.description}
          </span>
        </TableCell>

        {/* Published Date */}
        <TableCell className="font-mono text-xs text-muted-foreground py-3 whitespace-nowrap">
          <div className="flex items-center gap-1">
            <CalendarDays className="w-3 h-3 opacity-50" />
            {cve.publishedDate ?? "—"}
          </div>
        </TableCell>

        {/* Patch Available */}
        <TableCell className="text-center py-3">
          {cve.patchAvailable ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500/30 text-[10px] font-mono">
              YES
            </Badge>
          ) : (
            <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/30 text-[10px] font-mono">
              NO
            </Badge>
          )}
        </TableCell>

        {/* Expand indicator */}
        <TableCell className="py-3 text-right">
          <Info className={`w-3.5 h-3.5 transition-colors ${expanded ? "text-primary" : "text-muted-foreground/40"}`} />
        </TableCell>
      </motion.tr>

      {/* Expanded detail row */}
      {expanded && (
        <tr className="border-border/10 bg-muted/10">
          <TableCell colSpan={8} className="p-0">
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              className="px-6 py-4 space-y-3"
            >
              <div className="grid md:grid-cols-3 gap-4">
                <div className="space-y-1">
                  <p className="text-[10px] font-mono uppercase text-muted-foreground">CVE Identifier</p>
                  <p className="font-mono text-sm font-bold text-primary">{cve.cveId}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-[10px] font-mono uppercase text-muted-foreground">Affected Component</p>
                  <p className="font-mono text-sm flex items-center gap-1">
                    <Layers className="w-3 h-3 text-primary" />
                    {cve.affectedComponent}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-[10px] font-mono uppercase text-muted-foreground">Published</p>
                  <p className="font-mono text-sm">{cve.publishedDate ?? "Unknown"}</p>
                </div>
              </div>
              <div className="space-y-1">
                <p className="text-[10px] font-mono uppercase text-muted-foreground">Full Description</p>
                <p className="text-sm leading-relaxed text-foreground/80 bg-background/50 border border-border/30 p-3 rounded-md">
                  {cve.description}
                </p>
              </div>
              <div className="flex gap-3">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 font-mono text-xs text-primary hover:underline"
                >
                  <ExternalLink className="w-3 h-3" /> NVD Detail Page
                </a>
                <a
                  href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.cveId}`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 font-mono text-xs text-primary hover:underline"
                >
                  <ExternalLink className="w-3 h-3" /> MITRE CVE Entry
                </a>
              </div>
            </motion.div>
          </TableCell>
        </tr>
      )}
    </>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CveIntelligence() {
  const params = useParams();
  const firmwareId = parseInt(params.firmwareId || "0", 10);

  const [search, setSearch]               = useState("");
  const [sortKey, setSortKey]             = useState<SortKey>("severity");
  const [sortDir, setSortDir]             = useState<SortDir>("desc");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const { data: cves, isLoading: loadingCves } = useGetCveMatches(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetCveMatchesQueryKey(firmwareId) },
  });

  const { data: cvss, isLoading: loadingCvss } = useGetCvssScores(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetCvssScoresQueryKey(firmwareId) },
  });

  if (!firmwareId) return <div>Invalid ID</div>;

  // ─── Derived data ──────────────────────────────────────────────────────────

  const filteredCves = useMemo(() => {
    if (!cves) return [];
    let list = [...cves];

    if (severityFilter !== "all")
      list = list.filter(c => c.severity === severityFilter);

    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(c =>
        c.cveId.toLowerCase().includes(q) ||
        c.affectedComponent.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q)
      );
    }

    list.sort((a, b) => {
      let cmp = 0;
      if      (sortKey === "severity")      cmp = (SEVERITY_RANK[a.severity] ?? 0) - (SEVERITY_RANK[b.severity] ?? 0);
      else if (sortKey === "cvssScore")     cmp = a.cvssScore - b.cvssScore;
      else if (sortKey === "cveId")         cmp = a.cveId.localeCompare(b.cveId);
      else if (sortKey === "publishedDate") cmp = (a.publishedDate ?? "").localeCompare(b.publishedDate ?? "");
      else if (sortKey === "component")     cmp = a.affectedComponent.localeCompare(b.affectedComponent);
      return sortDir === "desc" ? -cmp : cmp;
    });

    return list;
  }, [cves, search, sortKey, sortDir, severityFilter]);

  // Unique components for the component breakdown panel
  const componentCounts = useMemo(() => {
    if (!cves) return [];
    const counts: Record<string, { count: number; maxScore: number; hasCritical: boolean }> = {};
    for (const c of cves) {
      const comp = c.affectedComponent || "unknown";
      if (!counts[comp]) counts[comp] = { count: 0, maxScore: 0, hasCritical: false };
      counts[comp].count++;
      if (c.cvssScore > counts[comp].maxScore) counts[comp].maxScore = c.cvssScore;
      if (c.severity === "critical") counts[comp].hasCritical = true;
    }
    return Object.entries(counts)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 8);
  }, [cves]);

  // Radar chart data — score categories
  const radarData = useMemo(() => {
    if (!cves || cves.length === 0) return [];
    const buckets = { "9–10": 0, "7–8.9": 0, "4–6.9": 0, "0–3.9": 0 };
    for (const c of cves) {
      const s = c.cvssScore;
      if (s >= 9)      buckets["9–10"]++;
      else if (s >= 7) buckets["7–8.9"]++;
      else if (s >= 4) buckets["4–6.9"]++;
      else             buckets["0–3.9"]++;
    }
    return Object.entries(buckets).map(([range, count]) => ({ range, count }));
  }, [cves]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("desc"); }
  };

  const avgScore  = cvss?.averageScore ?? 0;
  const totalCves = cvss ? cvss.critical + cvss.high + cvss.medium + cvss.low : 0;

  // ─── Sub-components ────────────────────────────────────────────────────────

  function SortHead({ label, colKey }: { label: string; colKey: SortKey }) {
    const active = sortKey === colKey;
    return (
      <TableHead
        className="font-mono text-xs uppercase cursor-pointer select-none hover:text-primary transition-colors"
        onClick={() => toggleSort(colKey)}
      >
        <span className="flex items-center gap-1">
          {label}
          {active
            ? <ArrowUpDown className="w-3 h-3 text-primary" />
            : <ChevronsUpDown className="w-3 h-3 opacity-30" />}
        </span>
      </TableHead>
    );
  }

  const cvssChartData = cvss ? [
    { name: "Critical", value: cvss.critical, fill: severityColor("critical") },
    { name: "High",     value: cvss.high,     fill: severityColor("high") },
    { name: "Medium",   value: cvss.medium,   fill: severityColor("medium") },
    { name: "Low",      value: cvss.low,      fill: severityColor("low") },
  ].filter(d => d.value > 0) : [];

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">

      {/* ── Header ── */}
      <div className="flex items-center gap-4 mb-2">
        <Link href={`/scan/${firmwareId}`}>
          <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full">
            <ChevronLeft className="w-4 h-4" />
          </Button>
        </Link>
        <motion.h1
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="text-3xl font-bold font-mono text-primary flex items-center drop-shadow-[0_0_8px_rgba(0,255,255,0.5)]"
        >
          <Bug className="mr-3 text-primary" />
          CVE_INTELLIGENCE
        </motion.h1>
      </div>

      {/* ── KPI Cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: "Total CVEs",      value: loadingCvss ? null : totalCves,              icon: Bug,          color: "text-primary",      border: "border-primary/20"     },
          { label: "Critical",        value: loadingCvss ? null : (cvss?.critical ?? 0),  icon: TriangleAlert, color: "text-destructive",  border: "border-destructive/20" },
          { label: "High",            value: loadingCvss ? null : (cvss?.high ?? 0),      icon: ShieldAlert,  color: "text-orange-500",   border: "border-orange-500/20"  },
          { label: "Medium / Low",    value: loadingCvss ? null : ((cvss?.medium ?? 0) + (cvss?.low ?? 0)), icon: Info, color: "text-yellow-500", border: "border-yellow-500/20" },
          { label: "Patched",         value: loadingCves ? null : (cves?.filter(c => c.patchAvailable).length ?? 0), icon: ShieldCheck, color: "text-green-500", border: "border-green-500/20" },
        ].map(({ label, value, icon: Icon, color, border }, i) => (
          <motion.div key={label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <Card className={`border ${border} bg-card/80 backdrop-blur-md`}>
              <CardContent className="p-4 flex items-center gap-3">
                <div className={`p-2 rounded-md bg-background/60 border ${border}`}>
                  <Icon className={`w-5 h-5 ${color}`} />
                </div>
                <div>
                  <p className="text-[10px] font-mono text-muted-foreground uppercase">{label}</p>
                  {value === null
                    ? <Skeleton className="h-7 w-10 mt-0.5" />
                    : <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
                  }
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* ── Charts Row ── */}
      <div className="grid md:grid-cols-3 gap-6">

        {/* Bar chart — severity distribution */}
        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg md:col-span-1">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2">
              Severity Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loadingCvss
              ? <Skeleton className="h-[180px] w-full" />
              : cvssChartData.length > 0
                ? (
                  <div className="h-[180px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={cvssChartData} margin={{ top: 20, right: 8, left: -20, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                        <XAxis dataKey="name" stroke="hsl(var(--muted-foreground))" fontSize={10} tickLine={false} axisLine={false} fontFamily="monospace" />
                        <YAxis stroke="hsl(var(--muted-foreground))" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
                        <RechartsTooltip
                          cursor={{ fill: "hsl(var(--muted))", opacity: 0.15 }}
                          contentStyle={{ backgroundColor: "hsl(var(--card))", borderColor: "hsl(var(--border))", fontFamily: "monospace", fontSize: "11px", borderRadius: "6px" }}
                          formatter={(v: number) => [`${v} CVEs`, "Count"]}
                        />
                        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                          <LabelList dataKey="value" position="top" style={{ fill: "hsl(var(--muted-foreground))", fontSize: 10, fontFamily: "monospace" }} />
                          {cvssChartData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )
                : <div className="h-[180px] flex items-center justify-center text-muted-foreground font-mono text-xs">No data</div>
            }
          </CardContent>
        </Card>

        {/* Average CVSS + breakdown */}
        <Card className="border-primary/20 bg-card/80 backdrop-blur-md shadow-[0_0_15px_rgba(0,255,255,0.05)] md:col-span-1">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2">
              Average CVSS Score
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center gap-3 pt-4">
            {loadingCvss ? (
              <Skeleton className="h-20 w-24 rounded-lg" />
            ) : (
              <>
                <div className={`text-6xl font-bold font-mono ${scoreTextClass(avgScore)}`}>
                  {avgScore.toFixed(1)}
                </div>
                <Badge
                  variant="outline"
                  className={`font-mono text-xs uppercase px-3 ${
                    avgScore >= 9 ? "bg-destructive/10 text-destructive border-destructive/30" :
                    avgScore >= 7 ? "bg-orange-500/10 text-orange-500 border-orange-500/30" :
                    avgScore >= 4 ? "bg-yellow-500/10 text-yellow-500 border-yellow-500/30" :
                    "bg-green-500/10 text-green-500 border-green-500/30"
                  }`}
                >
                  {scoreLabel(avgScore)} Risk
                </Badge>
                {/* Score scale bar */}
                <div className="w-full mt-2 space-y-1">
                  <div className="h-2 w-full rounded-full overflow-hidden flex">
                    <div className="h-full bg-green-500/70"  style={{ width: "40%" }} />
                    <div className="h-full bg-yellow-500/70" style={{ width: "30%" }} />
                    <div className="h-full bg-orange-500/70" style={{ width: "20%" }} />
                    <div className="h-full bg-destructive/70" style={{ width: "10%" }} />
                  </div>
                  <div
                    className="w-2 h-2 rounded-full bg-white border-2 border-primary -mt-3 relative transition-all"
                    style={{ marginLeft: `calc(${Math.min(99, (avgScore / 10) * 100)}% - 4px)` }}
                  />
                  <div className="flex justify-between text-[9px] font-mono text-muted-foreground mt-1">
                    <span>0</span><span>4</span><span>7</span><span>9</span><span>10</span>
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* CVSS Score Range Radar */}
        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg md:col-span-1">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2">
              Score Range Spread
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loadingCves
              ? <Skeleton className="h-[180px] w-full" />
              : radarData.length > 0
                ? (
                  <div className="h-[180px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadarChart data={radarData}>
                        <PolarGrid stroke="hsl(var(--border))" />
                        <PolarAngleAxis dataKey="range" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10, fontFamily: "monospace" }} />
                        <Radar dataKey="count" stroke="hsl(var(--primary))" fill="hsl(var(--primary))" fillOpacity={0.25} />
                        <RechartsTooltip
                          contentStyle={{ backgroundColor: "hsl(var(--card))", borderColor: "hsl(var(--border))", fontFamily: "monospace", fontSize: "11px", borderRadius: "6px" }}
                          formatter={(v: number) => [`${v} CVEs`, "Count"]}
                        />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                )
                : <div className="h-[180px] flex items-center justify-center text-muted-foreground font-mono text-xs">No data</div>
            }
          </CardContent>
        </Card>
      </div>

      {/* ── Component Breakdown ── */}
      {!loadingCves && componentCounts.length > 0 && (
        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2 flex items-center gap-2">
              <Layers className="w-4 h-4" /> Affected Components
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {componentCounts.map(([comp, info]) => (
                <div
                  key={comp}
                  className={`p-3 rounded-md border bg-background/50 space-y-1 cursor-pointer transition-all hover:border-primary/50 ${
                    info.hasCritical ? "border-destructive/30" : "border-border/50"
                  }`}
                  onClick={() => { setSeverityFilter("all"); setSearch(comp); }}
                  title="Click to filter by this component"
                >
                  <p className="font-mono text-xs font-bold text-foreground truncate">{comp}</p>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-lg font-bold text-primary">{info.count}</span>
                    <span className={`font-mono text-xs ${scoreTextClass(info.maxScore)}`}>
                      max {info.maxScore.toFixed(1)}
                    </span>
                  </div>
                  {info.hasCritical && (
                    <Badge variant="outline" className="text-[9px] font-mono bg-destructive/10 text-destructive border-destructive/30 px-1.5 py-0">
                      CRITICAL
                    </Badge>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── CVE Table ── */}
      <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg">
        <CardHeader>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-border/50 pb-3">
            <CardTitle className="font-mono text-sm uppercase text-primary flex items-center gap-2">
              <Bug className="w-4 h-4" />
              CVE Database
              {!loadingCves && cves && (
                <span className="text-muted-foreground font-normal">
                  ({filteredCves.length}/{cves.length})
                </span>
              )}
            </CardTitle>
            <div className="flex flex-wrap items-center gap-2">
              {/* Severity filter pills */}
              {(["all", "critical", "high", "medium", "low"] as const).map(sev => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`font-mono text-[10px] uppercase px-2.5 py-1 rounded border transition-all ${
                    severityFilter === sev
                      ? sev === "critical" ? "bg-destructive/20 text-destructive border-destructive/40"
                        : sev === "high"   ? "bg-orange-500/20 text-orange-500 border-orange-500/40"
                        : sev === "medium" ? "bg-yellow-500/20 text-yellow-500 border-yellow-500/40"
                        : sev === "low"    ? "bg-green-500/20  text-green-500  border-green-500/40"
                        :                   "bg-primary/20 text-primary border-primary/40"
                      : "bg-transparent text-muted-foreground border-border/50 hover:border-border"
                  }`}
                >
                  {sev}
                </button>
              ))}
              {/* Search box */}
              <div className="relative">
                <SearchIcon className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
                <Input
                  placeholder="CVE ID, component, description…"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  className="pl-7 h-8 font-mono text-xs bg-background/50 border-border/50 w-60 focus:border-primary/50"
                />
              </div>
              {(search || severityFilter !== "all") && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 font-mono text-xs text-muted-foreground"
                  onClick={() => { setSearch(""); setSeverityFilter("all"); }}
                >
                  Clear
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {loadingCves ? (
            <div className="p-6 space-y-2">
              {[1, 2, 3, 4, 5].map(i => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : filteredCves.length > 0 ? (
            <div className="max-h-[700px] overflow-auto custom-scrollbar">
              <Table>
                <TableHeader className="bg-muted/10 sticky top-0 z-10 shadow-sm">
                  <TableRow className="border-border/50">
                    <SortHead label="CVE ID"    colKey="cveId" />
                    <SortHead label="Severity"  colKey="severity" />
                    <SortHead label="Score"     colKey="cvssScore" />
                    <SortHead label="Component" colKey="component" />
                    <TableHead className="font-mono text-xs uppercase w-[38%]">Description</TableHead>
                    <SortHead label="Published" colKey="publishedDate" />
                    <TableHead className="font-mono text-xs uppercase text-center">Patch</TableHead>
                    <TableHead className="w-8" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredCves.map((cve, idx) => (
                    <CveRow key={cve.id} cve={cve} idx={idx} />
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : cves && cves.length > 0 ? (
            <div className="p-10 text-center flex flex-col items-center gap-3">
              <SearchIcon className="w-10 h-10 text-muted-foreground/30" />
              <p className="font-mono text-muted-foreground">No CVEs match your filter.</p>
              <Button
                variant="ghost"
                size="sm"
                className="font-mono text-xs"
                onClick={() => { setSearch(""); setSeverityFilter("all"); }}
              >
                Clear Filters
              </Button>
            </div>
          ) : (
            <div className="p-14 text-center flex flex-col items-center gap-4">
              <ShieldCheck className="w-16 h-16 text-green-500/30" />
              <div>
                <p className="font-mono text-xl text-muted-foreground">NO_CVE_MATCHES</p>
                <p className="text-sm text-muted-foreground/60 mt-1">
                  No known CVEs were matched against the detected firmware components.
                </p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

    </div>
  );
}
