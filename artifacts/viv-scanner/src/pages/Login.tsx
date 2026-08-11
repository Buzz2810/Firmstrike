import { Shield, Mail, Lock, ArrowRight } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Link } from "wouter";
import { useState } from "react";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [expectingOtp, setExpectingOtp] = useState(false);
  const [message, setMessage] = useState(null as string | null);

  async function submitLogin() {
    setMessage(null);
    const res = await fetch(`/api/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
    const body = await res.json();
    if (!res.ok) {
      setMessage(body?.error || "Login failed");
      return;
    }
    // API returns OTP for dev/testing; prompt user to enter it
    setExpectingOtp(true);
    setMessage(`OTP sent (for dev: ${body?.otp ?? "hidden"})`);
  }

  async function submitVerify() {
    setMessage(null);
    const res = await fetch(`/api/auth/verify-otp`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, otp }) });
    const body = await res.json();
    if (!res.ok) {
      setMessage(body?.error || "OTP verify failed");
      return;
    }
    // store token and redirect (simple)
    localStorage.setItem("token", body.token);
    setMessage("Authenticated");
    window.location.href = "/";
  }

  return (
    <div className="min-h-screen w-full bg-[#0a0f14] flex items-center justify-center relative overflow-hidden font-sans">
      <div className="fixed inset-0 pointer-events-none opacity-20 mix-blend-screen" 
           style={{ 
             backgroundImage: 'linear-gradient(to right, hsl(var(--primary) / 0.2) 1px, transparent 1px), linear-gradient(to bottom, hsl(var(--primary) / 0.2) 1px, transparent 1px)', 
             backgroundSize: '40px 40px',
             maskImage: 'radial-gradient(ellipse at center, black 40%, transparent 80%)'
           }} />

      <Card className="w-full max-w-md border-primary/30 bg-card/60 backdrop-blur-xl shadow-[0_0_30px_rgba(0,255,255,0.1)] relative z-10">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary to-transparent" />
        <CardHeader className="space-y-1 pb-8 text-center">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center shadow-[0_0_15px_rgba(0,255,255,0.2)]">
              <Shield className="w-8 h-8 text-primary" />
            </div>
          </div>
          <CardTitle className="text-2xl font-mono tracking-wider text-primary drop-shadow-[0_0_8px_rgba(0,255,255,0.5)]">FIRMSTRIKE</CardTitle>
          <CardDescription className="font-mono text-xs uppercase tracking-widest text-muted-foreground mt-2">
            Secure Authentication Gateway
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-5">
          <div className="space-y-2">
            <p className="font-mono text-xs uppercase text-muted-foreground">Analyst Email</p>
            <div className="flex items-center gap-3 px-4 py-3 rounded-md border border-border/40 bg-background/30">
              <Mail className="w-4 h-4 text-primary/60 shrink-0" />
                <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="analyst@soc.local" className="bg-transparent outline-none w-full font-mono text-sm text-muted-foreground/70" />
            </div>
          </div>

          <div className="space-y-2">
            <p className="font-mono text-xs uppercase text-muted-foreground">Access Token</p>
            <div className="flex items-center gap-3 px-4 py-3 rounded-md border border-border/40 bg-background/30">
              <Lock className="w-4 h-4 text-primary/60 shrink-0" />
                <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" placeholder="••••••" className="bg-transparent outline-none w-full font-mono text-sm text-muted-foreground/70" />
            </div>
          </div>

            {!expectingOtp ? (
              <div onClick={submitLogin} className="cursor-pointer flex items-center justify-center gap-2 w-full py-3 rounded-md border border-primary/30 bg-primary/5 font-mono text-xs uppercase tracking-wider text-primary/60">
                <span>Initialize Session</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </div>
            ) : (
              <div className="space-y-3">
                <div className="space-y-2">
                  <p className="font-mono text-xs uppercase text-muted-foreground">One-Time Password (OTP)</p>
                  <div className="flex items-center gap-3 px-4 py-3 rounded-md border border-border/40 bg-background/30">
                    <input value={otp} onChange={(e) => setOtp(e.target.value)} placeholder="123456" className="bg-transparent outline-none w-full font-mono text-sm text-muted-foreground/70" />
                  </div>
                </div>
                <div onClick={submitVerify} className="cursor-pointer flex items-center justify-center gap-2 w-full py-3 rounded-md border border-primary/30 bg-primary/5 font-mono text-xs uppercase tracking-wider text-primary/60">
                  <span>Verify OTP</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>
            )}

            {message && <div className="mt-2 text-center text-sm font-mono text-primary">{message}</div>}
        </CardContent>

        <CardFooter className="flex justify-center border-t border-border/30 pt-6">
          <p className="text-xs text-muted-foreground font-mono">
            Unregistered entity?{" "}
            <Link href="/register">
              <span className="text-primary hover:underline cursor-pointer">Request Access</span>
            </Link>
          </p>
        </CardFooter>
      </Card>
    </div>
  );
}
