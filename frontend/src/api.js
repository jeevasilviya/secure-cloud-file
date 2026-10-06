const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "")
  .trim()
  .replace(/\/+$/, "");

export const TOKEN_KEY = "secure-cloud-vault-token";

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY);
}

export function apiErrorMessage(status, detail) {
  if (status === 401) return "Your session has expired. Please sign in again.";
  if (status === 403) return detail || "You are not authorized to perform this action.";
  if (status === 404) return detail || "The requested file could not be found.";
  if (status === 413) return detail || "This file exceeds the 10 MiB upload limit.";
  if (status === 503) return "The virus scanner is unavailable. The upload was not accepted.";
  if (status === 0) return "Could not reach the API. Check that the backend is running.";
  return detail || "The request could not be completed. Please try again.";
}

async function parseError(response) {
  let detail;
  try {
    const payload = await response.json();
    detail = typeof payload.detail === "string" ? payload.detail : undefined;
  } catch {
    detail = undefined;
  }
  return apiErrorMessage(response.status, detail);
}

async function request(path, options = {}) {
  const token = getToken();
  const headers = new Headers(options.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);

  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers,
    });
  } catch {
    throw new Error(apiErrorMessage(0));
  }

  if (response.status === 401 && token) {
    clearToken();
    window.dispatchEvent(new Event("vault:unauthorized"));
  }
  if (!response.ok) throw new Error(await parseError(response));
  return response;
}

export async function registerUser(values) {
  const response = await request("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(values),
  });
  return response.json();
}

export async function loginUser(values) {
  const response = await request("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(values),
  });
  return response.json();
}

export async function getProfile() {
  const response = await request("/profile");
  return response.json();
}

export async function getFiles() {
  const response = await request("/files");
  return response.json();
}

export function uploadFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE_URL}/upload`);
    const token = getToken();
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);

    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    });

    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText));
        } catch {
          reject(new Error("The API returned an invalid upload response."));
        }
        return;
      }

      if (xhr.status === 401 && token) {
        clearToken();
        window.dispatchEvent(new Event("vault:unauthorized"));
      }

      let detail;
      try {
        const payload = JSON.parse(xhr.responseText);
        detail = typeof payload.detail === "string" ? payload.detail : undefined;
      } catch {
        detail = undefined;
      }
      reject(new Error(apiErrorMessage(xhr.status, detail)));
    });

    xhr.addEventListener("error", () => reject(new Error(apiErrorMessage(0))));
    xhr.addEventListener("abort", () => reject(new Error("Upload was cancelled.")));

    const formData = new FormData();
    formData.append("file", file);
    xhr.send(formData);
  });
}

export async function downloadFile(file) {
  const response = await request(`/download/${encodeURIComponent(file.id)}`);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = file.filename || "download";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function deleteFile(fileId) {
  const response = await request(`/files/${encodeURIComponent(fileId)}`, {
    method: "DELETE",
  });
  return response.json();
}

export async function logout() {
  try {
    await request("/logout", { method: "POST" });
  } finally {
    clearToken();
  }
}
