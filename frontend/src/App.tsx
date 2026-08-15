import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme-provider";
import NotFound from "@/pages/not-found";
import { Layout } from "@/components/Layout";
import Dashboard from "@/pages/Dashboard";
import FirmwareLibrary from "@/pages/FirmwareLibrary";
import ScanDetails from "@/pages/ScanDetails";
import SecurityAnalysis from "@/pages/SecurityAnalysis";
import CveIntelligence from "@/pages/CveIntelligence";
import MalwareDetection from "@/pages/MalwareDetection";
import ReportsAi from "@/pages/ReportsAi";
import Login from "@/pages/Login";
import Register from "@/pages/Register";

const queryClient = new QueryClient();

function Router() {
  return (
    <Switch>
      <Route path="/login" component={Login} />
      <Route path="/register" component={Register} />
      <Route path="/">
        <Layout><Dashboard /></Layout>
      </Route>
      <Route path="/firmware">
        <Layout><FirmwareLibrary /></Layout>
      </Route>

      {/* Primary Scan ID routes */}
      <Route path="/scans/:scanId">
        {() => <Layout><ScanDetails /></Layout>}
      </Route>
      <Route path="/scans/:scanId/security">
        {() => <Layout><SecurityAnalysis /></Layout>}
      </Route>
      <Route path="/scans/:scanId/cve">
        {() => <Layout><CveIntelligence /></Layout>}
      </Route>
      <Route path="/scans/:scanId/malware">
        {() => <Layout><MalwareDetection /></Layout>}
      </Route>
      <Route path="/scans/:scanId/reports">
        {() => <Layout><ReportsAi /></Layout>}
      </Route>

      {/* Explicit sub-path routes */}
      <Route path="/security/scan/:scanId">
        {() => <Layout><SecurityAnalysis /></Layout>}
      </Route>
      <Route path="/cve/scan/:scanId">
        {() => <Layout><CveIntelligence /></Layout>}
      </Route>
      <Route path="/malware/scan/:scanId">
        {() => <Layout><MalwareDetection /></Layout>}
      </Route>
      <Route path="/reports/scan/:scanId">
        {() => <Layout><ReportsAi /></Layout>}
      </Route>

      {/* Backward-compatibility fallback routes */}
      <Route path="/scan/:firmwareId">
        {() => <Layout><ScanDetails /></Layout>}
      </Route>
      <Route path="/security/:firmwareId">
        {() => <Layout><SecurityAnalysis /></Layout>}
      </Route>
      <Route path="/cve/:firmwareId">
        {() => <Layout><CveIntelligence /></Layout>}
      </Route>
      <Route path="/malware/:firmwareId">
        {() => <Layout><MalwareDetection /></Layout>}
      </Route>
      <Route path="/reports/:firmwareId">
        {() => <Layout><ReportsAi /></Layout>}
      </Route>

      <Route>
        <Layout><NotFound /></Layout>
      </Route>
    </Switch>
  );
}

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="viv-scanner-theme">
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
            <Router />
          </WouterRouter>
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;
