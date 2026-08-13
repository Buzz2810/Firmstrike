import { useParams, Link } from "wouter";
import { 
  useGetFirmware, getGetFirmwareQueryKey,
  useGetSecurityScore, getGetSecurityScoreQueryKey,
  useGetHardcodedSecrets, getGetHardcodedSecretsQueryKey,
  useGetDangerousFunctions, getGetDangerousFunctionsQueryKey,
  useGetVulnerabilities, getGetVulnerabilitiesQueryKey
} from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ShieldAlert, AlertTriangle, Key, Code, ChevronLeft, Shield, Cpu, Building2 } from "lucide-react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, RadialBarChart, RadialBar, PolarAngleAxis, Cell } from "recharts";

export default function SecurityAnalysis() {
  const params = useParams();
  const firmwareId = parseInt(params.firmwareId || "0", 10);

  const { data: firmware, isLoading: loadingFw } = useGetFirmware(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetFirmwareQueryKey(firmwareId) }
  });

  const { data: score, isLoading: loadingScore } = useGetSecurityScore(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetSecurityScoreQueryKey(firmwareId) }
  });

  const { data: secrets, isLoading: loadingSecrets } = useGetHardcodedSecrets(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetHardcodedSecretsQueryKey(firmwareId) }
  });

  const { data: functions, isLoading: loadingFuncs } = useGetDangerousFunctions(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetDangerousFunctionsQueryKey(firmwareId) }
  });

  const { data: vulns, isLoading: loadingVulns } = useGetVulnerabilities(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetVulnerabilitiesQueryKey(firmwareId) }
  });

  if (!firmwareId) return <div>Invalid ID</div>;

  const getSeverityColor = (severity: string) => {
    switch(severity?.toLowerCase()) {
      case 'critical': return 'hsl(var(--destructive))';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#22c55e';
      default: return 'hsl(var(--primary))';
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch(severity?.toLowerCase()) {
      case 'critical': return <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/30 uppercase text-[10px]">Critical</Badge>;
      case 'high': return <Badge variant="outline" className="bg-orange-500/10 text-orange-500 border-orange-500/30 uppercase text-[10px]">High</Badge>;
      case 'medium': return <Badge variant="outline" className="bg-yellow-500/10 text-yellow-500 border-yellow-500/30 uppercase text-[10px]">Medium</Badge>;
      case 'low': return <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500/30 uppercase text-[10px]">Low</Badge>;
      default: return <Badge variant="outline" className="bg-blue-500/10 text-blue-500 border-blue-500/30 uppercase text-[10px]">{severity}</Badge>;
    }
  };

  const scoreData = score ? [
    { name: 'Score', value: score.overallScore, fill: getSeverityColor(score.riskLevel) }
  ] : [];

  const vulnData = score ? [
    { name: 'Critical', value: score.criticalCount, fill: getSeverityColor('critical') },
    { name: 'High', value: score.highCount, fill: getSeverityColor('high') },
    { name: 'Medium', value: score.mediumCount, fill: getSeverityColor('medium') },
    { name: 'Low', value: score.lowCount, fill: getSeverityColor('low') },
  ].filter(d => d.value > 0) : [];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4 mb-2">
        <Link href={`/firmware`}>
          <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full">
            <ChevronLeft className="w-4 h-4" />
          </Button>
        </Link>
        <motion.h1 
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="text-3xl font-bold font-mono text-primary flex items-center drop-shadow-[0_0_8px_rgba(0,255,255,0.5)]"
        >
          <ShieldAlert className="mr-3 text-primary" />
          SECURITY_ANALYSIS
        </motion.h1>
      </div>

      <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg">
        <CardContent className="p-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <div className="space-y-1">
              <p className="text-xs font-mono text-muted-foreground uppercase">Firmware</p>
              <p className="font-mono text-sm truncate">
                {loadingFw ? <Skeleton className="h-4 w-32" /> : firmware?.name || 'Unknown'}
              </p>
            </div>
            <div className="space-y-1">
              <p className="text-xs font-mono text-muted-foreground uppercase">Architecture</p>
              <p className="font-mono text-sm flex items-center">
                <Cpu className="w-3 h-3 mr-1 text-primary" />
                {loadingFw ? <Skeleton className="h-4 w-16" /> : firmware?.architecture || 'Unknown'}
              </p>
            </div>
            <div className="space-y-1">
              <p className="text-xs font-mono text-muted-foreground uppercase">Vendor</p>
              <p className="font-mono text-sm flex items-center">
                <Building2 className="w-3 h-3 mr-1 text-primary" />
                {loadingFw ? <Skeleton className="h-4 w-20" /> : firmware?.vendor || 'Unknown'}
              </p>
            </div>
            <div className="space-y-1">
              <p className="text-xs font-mono text-muted-foreground uppercase">Status</p>
              <p className="font-mono text-sm">
                {loadingFw ? <Skeleton className="h-4 w-20" /> : (firmware?.status?.toUpperCase() || 'UNKNOWN')}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid md:grid-cols-3 gap-6">
        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2 flex items-center">
              <Shield className="w-4 h-4 mr-2" /> Security Score
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center p-6">
            {loadingScore ? (
              <Skeleton className="h-48 w-48 rounded-full" />
            ) : score ? (
              <div className="relative w-48 h-48 flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <RadialBarChart 
                    cx="50%" cy="50%" 
                    innerRadius="70%" outerRadius="100%" 
                    barSize={15} data={scoreData} 
                    startAngle={180} endAngle={0}
                  >
                    <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
                    <RadialBar background dataKey="value" cornerRadius={10} />
                  </RadialBarChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center -mt-6">
                  <span className="text-4xl font-bold font-mono" style={{ color: getSeverityColor(score.riskLevel) }}>
                    {score.overallScore}
                  </span>
                  <span className="text-xs uppercase font-mono mt-1 text-muted-foreground">Score</span>
                </div>
                <div className="absolute bottom-4">
                  {getSeverityBadge(score.riskLevel)}
                </div>
              </div>
            ) : (
              <p className="text-muted-foreground font-mono">No score available</p>
            )}
          </CardContent>
        </Card>

        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg md:col-span-2">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2">Vulnerability Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            {loadingScore ? (
              <Skeleton className="h-48 w-full" />
            ) : vulnData.length > 0 ? (
              <div className="h-48 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={vulnData} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" horizontal={true} vertical={false} />
                    <XAxis type="number" stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                    <YAxis dataKey="name" type="category" stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                    <RechartsTooltip cursor={{fill: 'transparent'}} contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', fontFamily: 'var(--font-mono)', borderRadius: '4px' }} />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                      {vulnData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
               <p className="text-muted-foreground font-mono">No vulnerabilities found</p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2 flex items-center">
              <Key className="w-4 h-4 mr-2" /> Hardcoded Secrets
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {loadingSecrets ? (
              <div className="p-6 space-y-2">
                {[1,2,3].map(i => <Skeleton key={i} className="h-10 w-full" />)}
              </div>
            ) : secrets && secrets.length > 0 ? (
              <div className="max-h-[300px] overflow-auto custom-scrollbar">
                <Table>
                  <TableHeader className="bg-muted/10 sticky top-0">
                    <TableRow className="border-border/50">
                      <TableHead className="font-mono text-xs uppercase">Type</TableHead>
                      <TableHead className="font-mono text-xs uppercase">File:Line</TableHead>
                      <TableHead className="font-mono text-xs uppercase text-right">Severity</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {secrets.map(secret => (
                      <TableRow key={secret.id} className="border-border/20">
                        <TableCell className="font-mono text-xs text-foreground">{secret.type}</TableCell>
                        <TableCell className="font-mono text-[10px] text-muted-foreground break-all">
                          {secret.file}:{secret.line}
                        </TableCell>
                        <TableCell className="text-right">
                          {getSeverityBadge(secret.severity || 'medium')}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <div className="p-8 text-center text-muted-foreground font-mono">No secrets detected</div>
            )}
          </CardContent>
        </Card>

        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2 flex items-center">
              <Code className="w-4 h-4 mr-2" /> Dangerous Functions
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {loadingFuncs ? (
              <div className="p-6 space-y-2">
                {[1,2,3].map(i => <Skeleton key={i} className="h-10 w-full" />)}
              </div>
            ) : functions && functions.length > 0 ? (
              <div className="max-h-[300px] overflow-auto custom-scrollbar">
                <Table>
                  <TableHeader className="bg-muted/10 sticky top-0">
                    <TableRow className="border-border/50">
                      <TableHead className="font-mono text-xs uppercase">Function</TableHead>
                      <TableHead className="font-mono text-xs uppercase">File:Line</TableHead>
                      <TableHead className="font-mono text-xs uppercase text-right">Risk</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {functions.map(func => (
                      <TableRow key={func.id} className="border-border/20">
                        <TableCell className="font-mono text-xs text-foreground bg-muted/10 rounded px-2 font-bold">{func.name}()</TableCell>
                        <TableCell className="font-mono text-[10px] text-muted-foreground break-all">
                          {func.file}:{func.line}
                        </TableCell>
                        <TableCell className="text-right">
                          {getSeverityBadge(func.risk)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <div className="p-8 text-center text-muted-foreground font-mono">No dangerous functions detected</div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg">
        <CardHeader>
          <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2 flex items-center">
            <AlertTriangle className="w-4 h-4 mr-2" /> Discovered Vulnerabilities
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loadingVulns ? (
            <div className="p-6 space-y-2">
              {[1,2,3,4].map(i => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : vulns && vulns.length > 0 ? (
            <div className="max-h-[400px] overflow-auto custom-scrollbar">
              <Table>
                <TableHeader className="bg-muted/10 sticky top-0">
                  <TableRow className="border-border/50">
                    <TableHead className="font-mono text-xs uppercase">Severity</TableHead>
                    <TableHead className="font-mono text-xs uppercase">Type / File</TableHead>
                    <TableHead className="font-mono text-xs uppercase w-1/3">Description</TableHead>
                    <TableHead className="font-mono text-xs uppercase">CVSS</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {vulns.map(vuln => (
                    <TableRow key={vuln.id} className="border-border/20 hover:bg-muted/5">
                      <TableCell>{getSeverityBadge(vuln.severity)}</TableCell>
                      <TableCell>
                        <div className="font-mono text-sm font-bold text-foreground">{vuln.type}</div>
                        <div className="font-mono text-[10px] text-muted-foreground break-all">{vuln.affectedFile}</div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {vuln.description}
                      </TableCell>
                      <TableCell className="font-mono text-sm font-bold">
                        {vuln.cvssScore ? vuln.cvssScore.toFixed(1) : '-'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="p-8 text-center text-muted-foreground font-mono">No vulnerabilities detected</div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}