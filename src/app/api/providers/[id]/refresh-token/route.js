import { NextResponse } from "next/server";
import { getProviderConnectionById, updateProviderConnection } from "@/lib/localDb";

function decodeJwtPayload(token) {
  if (typeof token !== "string") throw new Error("Missing access token");

  const payload = token.split(".")[1];
  if (!payload) throw new Error("Invalid access token");

  const padded = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payload.length / 4) * 4, "=");
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
}

function buildUpdateData(tokenData, previousRefreshToken) {
  const updateData = {};

  if (tokenData.access_token) updateData.accessToken = tokenData.access_token;
  if (tokenData.refresh_token) updateData.refreshToken = tokenData.refresh_token;
  else updateData.refreshToken = previousRefreshToken;
  if (tokenData.token_type) updateData.tokenType = tokenData.token_type;
  if (tokenData.scope) updateData.scope = tokenData.scope;
  if (tokenData.expires_in) {
    updateData.expiresAt = new Date(Date.now() + tokenData.expires_in * 1000).toISOString();
    updateData.expiresIn = tokenData.expires_in;
  }

  return updateData;
}

export async function POST(request, { params }) {
  try {
    const { id } = await params;
    const connection = await getProviderConnectionById(id);

    if (!connection) {
      return NextResponse.json({ error: "Connection not found" }, { status: 404 });
    }

    if (!connection.accessToken || !connection.refreshToken) {
      return NextResponse.json({ error: "Connection has no refreshable token pair" }, { status: 400 });
    }

    let payload;
    try {
      payload = decodeJwtPayload(connection.accessToken);
    } catch {
      return NextResponse.json({ error: "Unable to decode access token" }, { status: 400 });
    }

    const clientId = payload?.client_id;
    if (!clientId) {
      return NextResponse.json({ error: "Access token has no client_id" }, { status: 400 });
    }

    const response = await fetch("https://auth.openai.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientId,
        grant_type: "refresh_token",
        refresh_token: connection.refreshToken,
      }),
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      return NextResponse.json({ error: data.error_description || data.error || "Token refresh failed" }, { status: response.status });
    }

    if (!data.access_token) {
      return NextResponse.json({ error: "Token refresh response missing access_token" }, { status: 502 });
    }

    const updateData = buildUpdateData(data, connection.refreshToken);
    const updated = await updateProviderConnection(id, updateData);

    return NextResponse.json({ ok: true, expiresAt: updated?.expiresAt || null });
  } catch (error) {
    console.log("Error refreshing provider token:", error);
    return NextResponse.json({ error: "Failed to refresh token" }, { status: 500 });
  }
}
