import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const { email, password } = await request.json();

  // TEST CREDENTIALS (for ZAP)
  const TEST_EMAIL = "testuser@test.local";
  const TEST_PASSWORD = "testpassword123";

  if (email === TEST_EMAIL && password === TEST_PASSWORD) {
    return NextResponse.json(
      { message: "Login success" },
      {
        status: 200,
        headers: {
          "Set-Cookie": `session=valid; Path=/; HttpOnly`
        }
      }
    );
  }

  return NextResponse.json({ message: "Invalid credentials" }, { status: 401 });
}
