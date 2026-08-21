import React, { useState } from 'react';
import { Shield, Mail, Lock, Eye, EyeOff, Users, AlertCircle, RefreshCw } from 'lucide-react';
import { useAuth } from '../lib/auth-context';
import { authApi } from '../lib/api';
import { WavyBackground } from '../app/components/ui/wavy-background';
import { NoiseBackground } from '../app/components/ui/noise-background';
import { MultiStepLoader } from '../app/components/ui/multi-step-loader';
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from '../app/components/ui/input-otp';
import { motion } from 'motion/react';

const loginLoadingStates = [
  { text: 'Verifying credentials...' },
  { text: 'Authenticating your identity...' },
  { text: 'Loading your workspace...' },
  { text: 'Fetching your data...' },
  { text: 'Setting up dashboard...' },
  { text: 'Almost there...' },
];

type ForgotStep = 'email' | 'otp' | 'newpass' | 'done';

export function NewLandingPage() {
  const { login } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [loginType, setLoginType] = useState<'admin' | 'user'>('admin');

  // Forgot password modal
  const [showForgot, setShowForgot] = useState(false);
  const [forgotStep, setForgotStep] = useState<ForgotStep>('email');
  const [forgotEmail, setForgotEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showNewPw, setShowNewPw] = useState(false);
  const [forgotError, setForgotError] = useState('');
  const [forgotLoading, setForgotLoading] = useState(false);

  const openForgot = () => {
    setShowForgot(true);
    setForgotStep('email');
    setForgotEmail('');
    setOtp('');
    setResetToken('');
    setNewPassword('');
    setForgotError('');
  };

  const handleSendOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotError('');
    setForgotLoading(true);
    try {
      await authApi.forgotPassword(forgotEmail);
      setForgotStep('otp');
    } catch (err: unknown) {
      setForgotError(err instanceof Error ? err.message : 'Failed to send code');
    } finally {
      setForgotLoading(false);
    }
  };

  const handleVerifyOtp = async () => {
    if (otp.length !== 6) return;
    setForgotError('');
    setForgotLoading(true);
    try {
      const { resetToken: token } = await authApi.verifyOtp(forgotEmail, otp);
      setResetToken(token);
      setForgotStep('newpass');
    } catch (err: unknown) {
      setForgotError(err instanceof Error ? err.message : 'Invalid code');
    } finally {
      setForgotLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotError('');
    setForgotLoading(true);
    try {
      await authApi.resetPassword(resetToken, newPassword);
      setForgotStep('done');
    } catch (err: unknown) {
      setForgotError(err instanceof Error ? err.message : 'Failed to reset password');
    } finally {
      setForgotLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    try {
      await login(email, password);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Invalid email or password');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen relative overflow-hidden">
      <MultiStepLoader loadingStates={loginLoadingStates} loading={isLoading} duration={800} loop={false} />
      {/* ── Forgot Password Modal ─────────────────────────── */}
      {showForgot && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md mx-4 bg-slate-900/80 backdrop-blur-xl border border-slate-700/60 rounded-3xl shadow-2xl overflow-hidden">

            {/* Step 1 — Email */}
            {forgotStep === 'email' && (
              <div className="p-8">
                <h2 className="text-xl font-bold text-white mb-1">Forgot password?</h2>
                <p className="text-sm text-slate-400 mb-6">Enter your email and we'll send you a 6-digit code.</p>
                <form onSubmit={handleSendOtp} className="space-y-4">
                  {forgotError && (
                    <div className="flex items-center gap-2 p-3 bg-red-900/30 border border-red-500/40 rounded-xl text-red-400 text-sm">
                      <AlertCircle className="w-4 h-4 shrink-0" /> {forgotError}
                    </div>
                  )}
                  <div className="relative">
                    <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                    <input
                      type="email"
                      placeholder="your@email.com"
                      value={forgotEmail}
                      onChange={e => setForgotEmail(e.target.value)}
                      required
                      className="w-full h-14 pl-12 pr-4 bg-slate-800/60 border border-slate-600/50 rounded-xl text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/20 transition-all"
                    />
                  </div>
                  <div className="flex gap-3 pt-1">
                    <button
                      type="submit"
                      disabled={forgotLoading}
                      className="flex-1 h-12 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-sm hover:opacity-90 disabled:opacity-60 transition-all"
                    >
                      {forgotLoading ? 'Sending…' : 'Send Code'}
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowForgot(false)}
                      className="px-5 h-12 rounded-xl border border-slate-600 text-slate-300 text-sm hover:bg-slate-800 transition-all"
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Step 2 — OTP */}
            {forgotStep === 'otp' && (
              <div className="p-8">
                <h2 className="text-xl font-bold text-white mb-1">Verify your email</h2>
                <p className="text-sm text-slate-400 mb-6">
                  Enter the 6-digit code sent to{' '}
                  <span className="text-slate-200 font-medium">{forgotEmail}</span>.
                </p>
                <div className="space-y-5">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-slate-300 font-medium">Verification code</span>
                    <button
                      type="button"
                      disabled={forgotLoading}
                      onClick={async () => {
                        setForgotError('');
                        setForgotLoading(true);
                        try { await authApi.forgotPassword(forgotEmail); }
                        catch { /* silent */ }
                        finally { setForgotLoading(false); setOtp(''); }
                      }}
                      className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors disabled:opacity-50"
                    >
                      <RefreshCw className="w-3 h-3" /> Resend
                    </button>
                  </div>

                  <div className="flex justify-center">
                    <InputOTP maxLength={6} value={otp} onChange={setOtp}>
                      <InputOTPGroup className="*:data-[slot=input-otp-slot]:h-12 *:data-[slot=input-otp-slot]:w-11 *:data-[slot=input-otp-slot]:text-xl *:data-[slot=input-otp-slot]:bg-slate-800 *:data-[slot=input-otp-slot]:text-white *:data-[slot=input-otp-slot]:border-slate-600">
                        <InputOTPSlot index={0} />
                        <InputOTPSlot index={1} />
                        <InputOTPSlot index={2} />
                      </InputOTPGroup>
                      <InputOTPSeparator className="mx-2 text-slate-500" />
                      <InputOTPGroup className="*:data-[slot=input-otp-slot]:h-12 *:data-[slot=input-otp-slot]:w-11 *:data-[slot=input-otp-slot]:text-xl *:data-[slot=input-otp-slot]:bg-slate-800 *:data-[slot=input-otp-slot]:text-white *:data-[slot=input-otp-slot]:border-slate-600">
                        <InputOTPSlot index={3} />
                        <InputOTPSlot index={4} />
                        <InputOTPSlot index={5} />
                      </InputOTPGroup>
                    </InputOTP>
                  </div>

                  {forgotError && (
                    <div className="flex items-center gap-2 p-3 bg-red-900/30 border border-red-500/40 rounded-xl text-red-400 text-sm">
                      <AlertCircle className="w-4 h-4 shrink-0" /> {forgotError}
                    </div>
                  )}
                  <p className="text-xs text-slate-500 text-center">Didn't get the code? Check your spam folder or resend above.</p>

                  <div className="flex gap-3 pt-1">
                    <button
                      type="button"
                      onClick={handleVerifyOtp}
                      disabled={otp.length !== 6 || forgotLoading}
                      className="flex-1 h-12 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-sm hover:opacity-90 disabled:opacity-40 transition-all"
                    >
                      {forgotLoading ? 'Verifying…' : 'Verify Code'}
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowForgot(false)}
                      className="px-5 h-12 rounded-xl border border-slate-600 text-slate-300 text-sm hover:bg-slate-800 transition-all"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Step 3 — New password */}
            {forgotStep === 'newpass' && (
              <div className="p-8">
                <h2 className="text-xl font-bold text-white mb-1">Set new password</h2>
                <p className="text-sm text-slate-400 mb-6">Choose a strong password (min. 8 characters).</p>
                <form onSubmit={handleResetPassword} className="space-y-4">
                  {forgotError && (
                    <div className="flex items-center gap-2 p-3 bg-red-900/30 border border-red-500/40 rounded-xl text-red-400 text-sm">
                      <AlertCircle className="w-4 h-4 shrink-0" /> {forgotError}
                    </div>
                  )}
                  <div className="relative">
                    <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                    <input
                      type={showNewPw ? 'text' : 'password'}
                      placeholder="Min 8 characters"
                      value={newPassword}
                      onChange={e => setNewPassword(e.target.value)}
                      required
                      minLength={8}
                      className="w-full h-14 pl-12 pr-12 bg-slate-800/60 border border-slate-600/50 rounded-xl text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/20 transition-all"
                    />
                    <button
                      type="button"
                      onClick={() => setShowNewPw(v => !v)}
                      className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      {showNewPw ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                  <div className="flex gap-3 pt-1">
                    <button
                      type="submit"
                      disabled={forgotLoading}
                      className="flex-1 h-12 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-sm hover:opacity-90 disabled:opacity-60 transition-all"
                    >
                      {forgotLoading ? 'Saving…' : 'Reset Password'}
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowForgot(false)}
                      className="px-5 h-12 rounded-xl border border-slate-600 text-slate-300 text-sm hover:bg-slate-800 transition-all"
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Step 4 — Done */}
            {forgotStep === 'done' && (
              <div className="p-8 text-center space-y-4">
                <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto">
                  <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                </div>
                <h2 className="text-xl font-bold text-white">Password reset!</h2>
                <p className="text-sm text-slate-400">Your password has been updated. You can now sign in with your new password.</p>
                <button
                  onClick={() => setShowForgot(false)}
                  className="w-full h-12 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-sm hover:opacity-90 transition-all"
                >
                  Back to Sign In
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Hero Section with Wavy Background */}
      <WavyBackground
        backgroundFill="linear-gradient(to bottom, #0f172a, #1e293b)"
        colors={['#3b82f6', '#8b5cf6', '#6366f1', '#a855f7', '#06b6d4']}
        waveOpacity={0.3}
        speed="slow"
        containerClassName="min-h-screen"
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center mb-12"
          >
            <div className="flex items-center justify-center gap-3 mb-3">
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
                className="w-14 h-14 flex items-center justify-center drop-shadow-2xl"
              >
                <img src="/logo.png" alt="Pii Sanitize" className="w-14 h-14 object-contain" />
              </motion.div>
              <h1 className="text-3xl md:text-4xl font-bold text-white">
                Pii Sanitize
              </h1>
            </div>
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.3 }}
              className="text-base text-slate-300"
            >
              Enterprise PII Sanitization Platform
            </motion.p>
          </motion.div>

          <div className="grid lg:grid-cols-2 gap-12 items-start max-w-6xl mx-auto">
            {/* Left Column - Hero Content */}
            <motion.div
              initial={{ opacity: 0, x: -50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.4, duration: 0.6 }}
              className="space-y-8 lg:pt-8"
            >
              <div>
                <h2 className="text-3xl md:text-4xl font-bold text-white mb-4 leading-tight">
                  Protect Sensitive Data with{' '}
                  <span className="bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                    AI-Powered Intelligence
                  </span>
                </h2>
                <p className="text-base text-slate-300 leading-relaxed">
                  Automatically detect, classify, and sanitize personally identifiable 
                  information across your entire data ecosystem. Ensure compliance and 
                  prevent data breaches.
                </p>
              </div>
            </motion.div>

            {/* Right Column - Glass Morphism Login Form */}
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.6, duration: 0.6 }}
              className="flex items-start justify-center"
            >
              {/* Glass Morphism Card */}
              <div className="w-full max-w-md bg-slate-900/40 backdrop-blur-xl border border-slate-700/50 rounded-3xl shadow-2xl p-8">
                {/* Role Selector */}
                <div className="flex gap-3 mb-8 p-1 bg-slate-800/60 rounded-2xl">
                  <button
                    onClick={() => setLoginType('admin')}
                    className={`flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 ${
                      loginType === 'admin'
                        ? 'bg-gradient-to-r from-cyan-400 to-blue-500 text-slate-900 shadow-lg'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Shield className="w-4 h-4" />
                    <span>Admin</span>
                  </button>
                  <button
                    onClick={() => setLoginType('user')}
                    className={`flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 ${
                      loginType === 'user'
                        ? 'bg-gradient-to-r from-cyan-400 to-blue-500 text-slate-900 shadow-lg'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Users className="w-4 h-4" />
                    <span>Staff</span>
                  </button>
                </div>

                <form onSubmit={handleLogin} className="space-y-5">
                  {/* Error Message */}
                  {error && (
                    <div className="flex items-center gap-2 p-3 bg-red-900/30 border border-red-500/40 rounded-xl text-red-400 text-sm">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      {error}
                    </div>
                  )}
                  <div className="relative">
                    <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400">
                      <Mail className="w-5 h-5" />
                    </div>
                    <input
                      id="email"
                      type="email"
                      placeholder={loginType === 'admin' ? 'Admin Email' : 'User Email'}
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      disabled={isLoading}
                      className="w-full h-14 pl-12 pr-4 bg-slate-800/40 border border-slate-600/50 rounded-xl text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/20 transition-all"
                    />
                  </div>

                  {/* Password Input */}
                  <div className="relative">
                    <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400">
                      <Lock className="w-5 h-5" />
                    </div>
                    <input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="Password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      disabled={isLoading}
                      className="w-full h-14 pl-12 pr-12 bg-slate-800/40 border border-slate-600/50 rounded-xl text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/20 transition-all"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      {showPassword ? (
                        <EyeOff className="w-5 h-5" />
                      ) : (
                        <Eye className="w-5 h-5" />
                      )}
                    </button>
                  </div>

                  {/* Login Button */}
                  <div className="pt-2">
                    <NoiseBackground
                      containerClassName="w-full p-[2px] rounded-full"
                      gradientColors={[
                        'rgb(99, 102, 241)',
                        'rgb(139, 92, 246)',
                        'rgb(168, 85, 247)',
                      ]}
                    >
                      <button
                        type="submit"
                        disabled={isLoading}
                        className={`w-full h-14 rounded-full bg-[#070709] text-white font-semibold text-base tracking-wide transition-all duration-150 flex items-center justify-center gap-2 ${
                          isLoading ? 'cursor-not-allowed opacity-70' : 'cursor-pointer hover:bg-[#0f0f14] active:scale-[0.98]'
                        }`}
                      >
                        <span>Login as {loginType === 'admin' ? 'Admin' : 'Staff'} &rarr;</span>
                      </button>
                    </NoiseBackground>
                  </div>
                </form>

                {/* Forgot Password */}
                <div className="text-center mt-6">
                  <button
                    type="button"
                    onClick={openForgot}
                    className="text-sm text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    Forgot Password?
                  </button>
                </div>

                {/* Demo Info */}
                <div className="mt-8 pt-6 border-t border-slate-700/50">
                  <div className="text-center">
                    <p className="text-xs text-slate-400 mb-3">
                      Default Credentials
                    </p>
                    <div className="space-y-2 text-xs text-slate-500">
                      <p>Admin: admin@pill.com / Admin@123</p>
                      <p>User: user@pill.com / User@123</p>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </WavyBackground>
    </div>
  );
}
