import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  ArrowDownToLine,
  ArrowRight,
  Check,
  CheckCircle2,
  Cloud,
  File,
  FileText,
  HardDrive,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldQuestion,
  Trash2,
  UploadCloud,
  UserRound,
  X,
} from "lucide-react";
import {
  clearToken,
  deleteFile,
  downloadFile,
  getFiles,
  getProfile,
  getToken,
  loginUser,
  logout,
  registerUser,
  setToken,
  uploadFile,
} from "./api.js";

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

function StatusNotice({ notice, onDismiss }) {
  if (!notice) return null;
  const isError = notice.type === "error";
  const Icon = isError ? AlertCircle : CheckCircle2;
  return (
    <div className={`notice ${isError ? "notice-error" : "notice-success"}`} role="status">
      <Icon size={18} aria-hidden="true" />
      <span>{notice.message}</span>
      <button
        className="icon-button notice-dismiss"
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss notification"
      >
        <X size={16} />
      </button>
    </div>
  );
}

function Brand({ compact = false }) {
  return (
    <div className={`brand ${compact ? "brand-compact" : ""}`}>
      <div className="brand-mark" aria-hidden="true">
        <Cloud size={20} strokeWidth={2.3} />
        <span />
      </div>
      <span className="brand-name">
        SECURE<span>CLOUD</span>
      </span>
    </div>
  );
}

function AuthScreen({ initialMode = "login", onAuthenticated }) {
  const [mode, setMode] = useState(initialMode);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);

  async function handleSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      if (mode === "register") {
        await registerUser({ username: username.trim(), email: email.trim(), password });
        setMode("login");
        setNotice({ type: "success", message: "Account created. Sign in to continue." });
        setPassword("");
      } else {
        const result = await loginUser({ username: username.trim(), password });
        if (!result.access_token) throw new Error("The API did not return an access token.");
        setToken(result.access_token);
        const profile = await getProfile();
        onAuthenticated(profile);
      }
    } catch (error) {
      if (mode === "login") clearToken();
      setNotice({ type: "error", message: error.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-layout">
      <section className="auth-aside">
        <div className="aside-grid" aria-hidden="true" />
        <Brand />
        <div className="aside-content">
          <span className="eyebrow"><ShieldCheck size={15} /> PRIVATE BY DESIGN</span>
          <h1>Your files.<br />Under your control.</h1>
          <p>
            A secure workspace for storing and managing your important files.
            Encrypted storage. Account-level access.
          </p>
          <div className="security-points">
            <div><LockKeyhole size={17} /><span>Encrypted at rest</span></div>
            <div><ShieldCheck size={17} /><span>Protected by your account</span></div>
            <div><KeyRound size={17} /><span>Private access tokens</span></div>
          </div>
        </div>
        <div className="aside-footer">SECURE CLOUD VAULT <span>•</span> LOCAL API</div>
      </section>

      <section className="auth-main">
        <div className="auth-mobile-brand"><Brand compact /></div>
        <div className="auth-card">
          <div className="auth-icon"><LockKeyhole size={22} /></div>
          <p className="eyebrow auth-eyebrow">SECURE FILE VAULT</p>
          <h2>{mode === "login" ? "Welcome back" : "Create your account"}</h2>
          <p className="auth-description">
            {mode === "login"
              ? "Sign in to access your encrypted workspace."
              : "Register to create your private file workspace."}
          </p>
          <StatusNotice notice={notice} onDismiss={() => setNotice(null)} />
          <form className="auth-form" onSubmit={handleSubmit}>
            <label>
              <span>Username</span>
              <div className="input-wrap"><UserRound size={17} /><input
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Your username"
                required
                maxLength={50}
              /></div>
            </label>
            {mode === "register" && (
              <label>
                <span>Email address</span>
                <div className="input-wrap"><FileText size={17} /><input
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@example.com"
                  required
                /></div>
              </label>
            )}
            <label>
              <span>Password</span>
              <div className="input-wrap"><KeyRound size={17} /><input
                type="password"
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter your password"
                required
              /></div>
            </label>
            <button className="button button-primary button-wide auth-submit" disabled={busy}>
              {busy ? <LoaderCircle className="spin" size={18} /> : null}
              {busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}
              {!busy && <ArrowRight size={17} />}
            </button>
          </form>
          <div className="auth-switch">
            {mode === "login" ? "New to Secure Cloud?" : "Already have an account?"}
            <button
              type="button"
              onClick={() => {
                setMode(mode === "login" ? "register" : "login");
                setNotice(null);
              }}
            >
              {mode === "login" ? "Create account" : "Sign in"}
            </button>
          </div>
        </div>
        <p className="auth-legal"><LockKeyhole size={13} /> Your password is sent only to the secure API for authentication.</p>
      </section>
    </main>
  );
}

function ScanBadge({ status }) {
  const normalized = (status || "unknown").toLowerCase();
  if (normalized === "clean") {
    return <span className="status-pill status-clean"><Check size={13} /> Clean</span>;
  }
  if (normalized === "deleted") {
    return <span className="status-pill status-muted">Deleted</span>;
  }
  return <span className="status-pill status-unknown"><ShieldQuestion size={13} /> {status || "Unknown"}</span>;
}

function FileRow({ file, onDownload, onDelete, busyAction }) {
  const extension = file.filename?.split(".").pop()?.slice(0, 4).toUpperCase() || "FILE";
  return (
    <article className="file-row">
      <div className={`file-type-icon type-${extension.toLowerCase()}`}>
        <FileText size={20} />
        <span>{extension}</span>
      </div>
      <div className="file-main">
        <div className="file-title-line">
          <p className="file-name" title={file.filename}>{file.filename}</p>
          <ScanBadge status={file.malware_status} />
        </div>
        <div className="file-meta">
          <span>{formatBytes(file.size_bytes)}</span><i />
          <span>{formatDate(file.uploaded_at)}</span>
        </div>
      </div>
      <div className="file-security">
        <LockKeyhole size={14} />
        <span>{file.encryption_status === "encrypted" ? "Encrypted" : "Storage status"}</span>
      </div>
      <div className="file-actions">
        <button
          className="icon-button"
          type="button"
          aria-label={`Download ${file.filename}`}
          title="Download"
          disabled={busyAction === `download-${file.id}`}
          onClick={() => onDownload(file)}
        >
          {busyAction === `download-${file.id}` ? <LoaderCircle className="spin" size={18} /> : <ArrowDownToLine size={18} />}
        </button>
        <button
          className="icon-button danger-hover"
          type="button"
          aria-label={`Delete ${file.filename}`}
          title="Delete"
          disabled={busyAction === `delete-${file.id}`}
          onClick={() => onDelete(file)}
        >
          {busyAction === `delete-${file.id}` ? <LoaderCircle className="spin" size={18} /> : <Trash2 size={18} />}
        </button>
      </div>
    </article>
  );
}

function Dashboard({ profile, onLogout }) {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploadProgress, setUploadProgress] = useState(null);
  const [busyAction, setBusyAction] = useState("");
  const [notice, setNotice] = useState(null);
  const [dragging, setDragging] = useState(false);

  const refreshFiles = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getFiles();
      setFiles(Array.isArray(result) ? result : []);
    } catch (error) {
      setNotice({ type: "error", message: error.message });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshFiles();
  }, [refreshFiles]);

  const totalBytes = useMemo(
    () => files.reduce((sum, file) => sum + (Number(file.size_bytes) || 0), 0),
    [files],
  );

  async function handleUpload(file) {
    if (!file) return;
    if (file.size > MAX_UPLOAD_BYTES) {
      setNotice({ type: "error", message: "This file exceeds the 10 MiB upload limit." });
      return;
    }
    setNotice(null);
    setUploadProgress(0);
    try {
      await uploadFile(file, setUploadProgress);
      setNotice({
        type: "success",
        message: "Upload accepted by the API after its scan check.",
      });
      await refreshFiles();
    } catch (error) {
      setNotice({ type: "error", message: error.message });
    } finally {
      setUploadProgress(null);
    }
  }

  async function handleDownload(file) {
    setBusyAction(`download-${file.id}`);
    setNotice(null);
    try {
      await downloadFile(file);
    } catch (error) {
      setNotice({ type: "error", message: error.message });
    } finally {
      setBusyAction("");
    }
  }

  async function handleDelete(file) {
    const confirmed = window.confirm(`Delete "${file.filename}"? This action cannot be undone.`);
    if (!confirmed) return;
    setBusyAction(`delete-${file.id}`);
    setNotice(null);
    try {
      await deleteFile(file.id);
      setFiles((current) => current.filter((item) => item.id !== file.id));
      setNotice({ type: "success", message: `${file.filename} was deleted.` });
    } catch (error) {
      setNotice({ type: "error", message: error.message });
    } finally {
      setBusyAction("");
    }
  }

  async function handleLogout() {
    try {
      await logout();
    } catch {
      clearToken();
    } finally {
      onLogout();
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-inner">
          <Brand compact />
          <div className="topbar-right">
            <div className="connection-indicator"><span /> API workspace</div>
            <div className="topbar-divider" />
            <div className="user-chip"><span className="avatar">{profile.username?.slice(0, 1).toUpperCase()}</span><span>{profile.username}</span></div>
            <button className="button button-quiet logout-button" type="button" onClick={handleLogout}>
              <LogOut size={16} /><span>Sign out</span>
            </button>
          </div>
        </div>
      </header>

      <main className="dashboard">
        <div className="dashboard-heading">
          <div>
            <p className="eyebrow">PERSONAL WORKSPACE</p>
            <h1>Good to see you, {profile.username}<span className="heading-period">.</span></h1>
            <p className="heading-subtitle">Your secure space for private files.</p>
          </div>
          <div className="security-state"><span className="security-state-icon"><ShieldCheck size={18} /></span><span><strong>Protected workspace</strong><small>Authenticated access enabled</small></span></div>
        </div>

        <StatusNotice notice={notice} onDismiss={() => setNotice(null)} />

        <section className="summary-grid" aria-label="Workspace summary">
          <div className="summary-card">
            <span className="summary-icon summary-blue"><File size={18} /></span>
            <span className="summary-label">Stored files</span>
            <strong>{loading ? "—" : files.length}</strong>
            <small>In your workspace</small>
          </div>
          <div className="summary-card">
            <span className="summary-icon summary-violet"><HardDrive size={18} /></span>
            <span className="summary-label">Storage used</span>
            <strong>{loading ? "—" : formatBytes(totalBytes)}</strong>
            <small>Based on original file sizes</small>
          </div>
          <div className="summary-card summary-card-wide">
            <span className="summary-icon summary-green"><ShieldCheck size={18} /></span>
            <span className="summary-label">File protection</span>
            <strong>Encrypted at rest</strong>
            <small>File contents are encrypted before storage by the API</small>
          </div>
        </section>

        <section className="upload-panel">
          <div className="section-heading">
            <div><h2>Upload a file</h2><p>Files are checked by the API before being stored.</p></div>
            <span className="limit-badge"><LockKeyhole size={13} /> Max 10 MiB</span>
          </div>
          <label
            className={`dropzone ${dragging ? "dropzone-active" : ""} ${uploadProgress !== null ? "dropzone-uploading" : ""}`}
            onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDragging(false);
              handleUpload(event.dataTransfer.files?.[0]);
            }}
          >
            <input
              type="file"
              disabled={uploadProgress !== null}
              onChange={(event) => {
                handleUpload(event.target.files?.[0]);
                event.target.value = "";
              }}
            />
            <span className="upload-icon">{uploadProgress !== null ? <LoaderCircle className="spin" size={23} /> : <UploadCloud size={23} />}</span>
            <span className="dropzone-copy">
              <strong>{uploadProgress !== null ? `Uploading… ${uploadProgress}%` : "Drop a file here or browse"}</strong>
              <small>{uploadProgress !== null ? "The API will respond when its scan check is complete." : "Choose a file from your device. Maximum size 10 MiB."}</small>
            </span>
            {uploadProgress !== null ? (
              <span className="upload-progress"><span style={{ width: `${uploadProgress}%` }} /></span>
            ) : (
              <span className="button button-secondary"><Plus size={16} /> Choose file</span>
            )}
          </label>
          <p className="scan-note"><ShieldQuestion size={14} /> Scan status is reported by the API. Live signature availability depends on server configuration.</p>
        </section>

        <section className="files-panel">
          <div className="section-heading files-heading">
            <div><h2>Your files <span className="count-bubble">{files.length}</span></h2><p>Only you can access files in this workspace.</p></div>
            <button className="button button-quiet refresh-button" type="button" onClick={refreshFiles} disabled={loading}>
              {loading ? <LoaderCircle className="spin" size={16} /> : <RefreshCw size={16} />} Refresh
            </button>
          </div>
          <div className="file-list">
            {loading ? (
              <div className="empty-state"><LoaderCircle className="spin" size={24} /><strong>Loading your files</strong><span>Connecting to your secure workspace…</span></div>
            ) : files.length ? (
              files.map((file) => (
                <FileRow
                  key={file.id}
                  file={file}
                  onDownload={handleDownload}
                  onDelete={handleDelete}
                  busyAction={busyAction}
                />
              ))
            ) : (
              <div className="empty-state">
                <span className="empty-icon"><File size={23} /></span>
                <strong>Your workspace is ready</strong>
                <span>Files you upload will appear here.</span>
              </div>
            )}
          </div>
        </section>

        <footer className="dashboard-footer">
          <span><LockKeyhole size={13} /> Your files are private to your account</span>
          <span>SECURE CLOUD VAULT <i /> LOCAL API</span>
        </footer>
      </main>
    </div>
  );
}

export default function App() {
  const [profile, setProfile] = useState(null);
  const [checkingSession, setCheckingSession] = useState(Boolean(getToken()));
  const [authMode, setAuthMode] = useState("login");

  useEffect(() => {
    const handleUnauthorized = () => {
      clearToken();
      setProfile(null);
      setAuthMode("login");
    };
    window.addEventListener("vault:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("vault:unauthorized", handleUnauthorized);
  }, []);

  useEffect(() => {
    if (!getToken()) {
      setCheckingSession(false);
      return;
    }
    let active = true;
    getProfile()
      .then((result) => { if (active) setProfile(result); })
      .catch(() => { if (active) clearToken(); })
      .finally(() => { if (active) setCheckingSession(false); });
    return () => { active = false; };
  }, []);

  if (checkingSession) {
    return <main className="launch-state"><Brand compact /><LoaderCircle className="spin" size={22} /><span>Checking your session…</span></main>;
  }

  if (profile) return <Dashboard profile={profile} onLogout={() => setProfile(null)} />;

  return <AuthScreen initialMode={authMode} onAuthenticated={setProfile} />;
}
