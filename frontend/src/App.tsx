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
      <Route path="/scan/:firmwareId">
        {(params) => <Layout><ScanDetails /></Layout>}
      </Route>
      <Route path="/security/:firmwareId">
        {(params) => <Layout><SecurityAnalysis /></Layout>}
      </Route>
      <Route path="/cve/:firmwareId">
        {(params) => <Layout><CveIntelligence /></Layout>}
      </Route>
      <Route path="/malware/:firmwareId">
        {(params) => <Layout><MalwareDetection /></Layout>}
      </Route>
      <Route path="/reports/:firmwareId">
        {(params) => <Layout><ReportsAi /></Layout>}
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
