import { useGetDashboardSummary, getGetDashboardSummaryQueryKey, useGetRecentActivity, getGetRecentActivityQueryKey, useGetRiskDistribution, getGetRiskDistributionQueryKey, useGetThreatTrend, getGetThreatTrendQueryKey } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Activity, ShieldAlert, Bug, Cpu, FileWarning, Clock } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { motion } from "framer-motion";

export default function Dashboard() {
  const { data: summary, isLoading: loadingSummary } = useGetDashboardSummary({
    query: { queryKey: getGetDashboardSummaryQueryKey() }
  });

  const { data: activity, isLoading: loadingActivity } = useGetRecentActivity({
    query: { queryKey: getGetRecentActivityQueryKey() }
  });

  const { data: riskDist, isLoading: loadingRisk } = useGetRiskDistribution({
    query: { queryKey: getGetRiskDistributionQueryKey() }
  });

  const { data: trend, isLoading: loadingTrend } = useGetThreatTrend({
    query: { queryKey: getGetThreatTrendQueryKey() }
  });

  if (loadingSummary) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold font-mono text-primary">SYSTEM_STATUS</h1>
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i} className="border-primary/20 bg-card/50 backdrop-blur">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <Skeleton className="h-4 w-24 bg-muted" />
                <Skeleton className="h-4 w-4 bg-muted" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-16 bg-muted mb-1" />
                <Skeleton className="h-3 w-32 bg-muted" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  const COLORS = {
    critical: "hsl(var(--destructive))",
    high: "#f97316", // orange-500
    medium: "#eab308", // yellow-500
    low: "#22c55e", // green-500
  };

  const pieData = riskDist ? [
    { name: "Critical", value: riskDist.critical, color: COLORS.critical },
    { name: "High", value: riskDist.high, color: COLORS.high },
    { name: "Medium", value: riskDist.medium, color: COLORS.medium },
    { name: "Low", value: riskDist.low, color: COLORS.low },
  ].filter(d => d.value > 0) : [];

  return (
    <div className="space-y-6">
      <motion.h1 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-3xl font-bold font-mono text-primary flex items-center drop-shadow-[0_0_8px_rgba(0,255,255,0.5)]"
      >
        <Activity className="mr-3 text-primary animate-pulse" />
        SYSTEM_STATUS
      </motion.h1>
      
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-primary/30 bg-card/80 backdrop-blur-md shadow-[0_0_15px_rgba(0,255,255,0.05)] hover:shadow-[0_0_25px_rgba(0,255,255,0.15)] transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">Total Firmware</CardTitle>
            <Cpu className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-foreground">{summary?.totalFirmware || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Processed binaries</p>
          </CardContent>
        </Card>
        
        <Card className="border-destructive/40 bg-card/80 backdrop-blur-md shadow-[0_0_15px_rgba(255,0,0,0.05)] hover:shadow-[0_0_25px_rgba(255,0,0,0.15)] transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">Critical Vulns</CardTitle>
            <ShieldAlert className="h-4 w-4 text-destructive animate-pulse" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-destructive drop-shadow-[0_0_5px_rgba(255,0,0,0.5)]">{summary?.criticalVulnerabilities || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Requires immediate action</p>
          </CardContent>
        </Card>
        
        <Card className="border-orange-500/40 bg-card/80 backdrop-blur-md shadow-[0_0_15px_rgba(255,165,0,0.05)] hover:shadow-[0_0_25px_rgba(255,165,0,0.15)] transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">High Vulns</CardTitle>
            <Bug className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-orange-500">{summary?.highVulnerabilities || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Severe risk identified</p>
          </CardContent>
        </Card>
        
        <Card className="border-primary/30 bg-card/80 backdrop-blur-md shadow-[0_0_15px_rgba(0,255,255,0.05)] hover:shadow-[0_0_25px_rgba(0,255,255,0.15)] transition-all duration-300">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">Threat Score</CardTitle>
            <Activity className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-foreground">{summary?.averageThreatScore?.toFixed(1) || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Global average risk</p>
          </CardContent>
        </Card>
      </div>
      
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        <Card className="border-border bg-card/80 backdrop-blur-md col-span-2 shadow-lg">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2">Threat Trend Analysis</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px] w-full mt-4">
              {loadingTrend ? (
                <Skeleton className="w-full h-full bg-muted/20" />
              ) : Array.isArray(trend) && trend.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trend} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                    <XAxis dataKey="date" stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                    <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                    <RechartsTooltip 
                      contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', fontFamily: 'var(--font-mono)' }}
                      itemStyle={{ color: 'hsl(var(--primary))' }}
                    />
                    <Area type="monotone" dataKey="score" stroke="hsl(var(--primary))" fillOpacity={1} fill="url(#colorScore)" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-muted-foreground font-mono">No trend data available</div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2">Risk Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px] w-full flex items-center justify-center">
              {loadingRisk ? (
                <Skeleton className="w-48 h-48 rounded-full bg-muted/20" />
              ) : pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip 
                      contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', fontFamily: 'var(--font-mono)', borderRadius: '4px' }}
                      itemStyle={{ fontWeight: 'bold' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-muted-foreground font-mono">No risk data available</div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-card/80 backdrop-blur-md md:col-span-2 lg:col-span-3 shadow-lg">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2">Live Activity Feed</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4 mt-4 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
              {loadingActivity ? (
                Array(5).fill(0).map((_, i) => (
                  <div key={i} className="flex items-start gap-4 p-3 rounded-md bg-muted/10 border border-border/50">
                    <Skeleton className="h-5 w-5 rounded-full bg-muted" />
                    <div className="space-y-2 flex-1">
                      <Skeleton className="h-4 w-3/4 bg-muted" />
                      <Skeleton className="h-3 w-1/4 bg-muted" />
                    </div>
                  </div>
                ))
              ) : Array.isArray(activity) && activity.length > 0 ? (
                activity.map((item) => (
                  <motion.div 
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    key={item.id} 
                    className="flex items-start gap-4 p-3 rounded-md bg-muted/10 border border-border/50 hover:bg-muted/20 transition-colors"
                  >
                    <div className={`p-1.5 rounded-full ${
                      item.severity === 'critical' ? 'bg-destructive/20 text-destructive' :
                      item.severity === 'high' ? 'bg-orange-500/20 text-orange-500' :
                      item.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-500' :
                      'bg-primary/20 text-primary'
                    }`}>
                      {item.type.includes('scan') ? <Clock className="w-4 h-4" /> : 
                       item.type.includes('vuln') ? <ShieldAlert className="w-4 h-4" /> :
                       <FileWarning className="w-4 h-4" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground">{item.message}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs text-muted-foreground font-mono">{new Date(item.timestamp).toLocaleString()}</span>
                        {item.firmwareName && (
                          <>
                            <span className="text-muted-foreground/50">•</span>
                            <span className="text-xs text-primary font-mono truncate">{item.firmwareName}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </motion.div>
                ))
              ) : (
                <div className="text-center p-8 text-muted-foreground font-mono border border-dashed border-border rounded-md">
                  No recent activity logged
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
