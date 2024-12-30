import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

// Define the paths you want to protect
const protectedPaths = [
  /\/shipping-address/,
  /\/payment-method/,
  /\/place-order/,
  /\/profile/,
  /\/user\/(.*)/,
  /\/order\/(.*)/,
  /\/admin/,
];

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Check if the request is for a protected path
  const isProtected = protectedPaths.some((path) =>
    typeof path === "string" ? pathname.startsWith(path) : path.test(pathname)
  );

  // If the path is protected, verify the token
  if (isProtected) {
    const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });

    if (!token) {
      // Redirect to sign-in if not authenticated
      return NextResponse.redirect(new URL("/sign-in", req.url));
    }
  }

  // Handle sessionCartId
  const sessionCartId = req.cookies.get("sessionCartId");
  if (!sessionCartId) {
    const newSessionCartId = crypto.randomUUID();
    const response = NextResponse.next();
    response.cookies.set("sessionCartId", newSessionCartId, { path: "/" });
    return response;
  }

  return NextResponse.next();
}


export const config = {
  matcher: [
    /^\/(shipping-address|payment-method|place-order|profile|user\/.*|order\/.*|admin).*$/,
  ],
};