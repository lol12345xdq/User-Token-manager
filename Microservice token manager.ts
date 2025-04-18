import jwt from "jsonwebtoken";
import db from "./db";
import { decryptToken, encryptToken } from "./encrypt";

function generateAuthorizationToken(id: string): string {
  return jwt.sign({ id }, process.env.SHARED_JWT_SECRET!, {
    expiresIn: "1h",
  });
}

export namespace Microservice {
  export async function storeAuthorizationToken(id: string): Promise<string> {
    try {
      const user = await db.user.findUnique({
        where: { id },
      });

      if (!user) {
        throw new Error("User not found");
      }

      const token = encryptToken(generateAuthorizationToken(id));

      // make sure no repeated tokens

      const userFromToken = await db.user.findFirst({
        where: { authorizationToken: token },
      });

      if (userFromToken) {
        throw new Error("Token already exists");
      }

      await db.user.update({
        where: { id },
        data: {
          authorizationToken: token,
        },
      });

      return token;
    } catch (error) {
      throw error;
    }
  }

  export async function validateAndRefreshAuthorizationToken(id: string) {
    try {
      const user = await db.user.findUnique({
        where: { id },
      });

      if (!user) {
        throw new Error("User not found");
      }

      const { authorizationToken } = user;

      if (!authorizationToken) {
        throw new Error("No authorization token found");
      }

      const decryptedAuthorizationToken = decryptToken(authorizationToken);

      console.log(decryptedAuthorizationToken);

      try {
        // Verify the token
        jwt.verify(decryptedAuthorizationToken, process.env.SHARED_JWT_SECRET!);
        return authorizationToken;
      } catch (error: any) {
        if (error.name === "TokenExpiredError") {
          const newToken = generateAuthorizationToken(id);

          const userFromToken = await db.user.findFirst({
            where: { authorizationToken: newToken },
          });

          if (userFromToken) {
            throw new Error("New token already exists");
          }

          await db.user.update({
            where: { id },
            data: {
              authorizationToken: newToken,
            },
          });

          return newToken;
        } else {
          throw new Error("Invalid token");
        }
      }
    } catch (error) {
      throw error;
    }
  }
}