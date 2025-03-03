import type { Express, Request, Response } from "express";

// Middleware to check if user is an admin
const isAdmin = (req: Request, res: Response, next: Function) => {
  if (req.isAuthenticated() && req.user?.role === "admin") {
    return next();
  }
  return res.status(403).json({ error: "FORBIDDEN", message: "Admin access only." });
};
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth } from "./auth";
import { 
  insertPasteSchema, 
  insertCommentSchema, 
  UserRole, 
  updateRoleSchema,
  insertAnnouncementSchema
} from "@shared/schema";
import { z } from "zod";
import multer from "multer";
import path from "path";
import fs from "fs";
import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';

// IP restriction middleware
const checkIPRestriction = async (req: Request, res: Response, next: Function) => {
  try {
    // Get the user's IP (accounting for proxies, which is common in Replit)
    const ip = req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '';

    // Skip check for static resources
    if (req.path.startsWith('/uploads/') || req.path.startsWith('/assets/')) {
      return next();
    }

    // Always allow access to the error page that will be shown for restricted IPs
    if (req.path === '/api/restricted') {
      return next();
    }

    // Skip check for admins that are already logged in
    if (req.isAuthenticated() && req.user?.isAdmin) {
      return next();
    }

    // Check if IP is restricted
    const isRestricted = await storage.isIPRestricted(ip);
    if (isRestricted) {
      // For API requests, return JSON
      if (req.path.startsWith('/api/')) {
        return res.status(403).json({
          error: 'IP_RESTRICTED',
          message: 'Your IP address has been restricted from accessing this site.'
        });
      }

      // For non-API requests, redirect to a page explaining the restriction
      return res.redirect('/restricted');
    }

    next();
  } catch (err) {
    console.error('Error checking IP restriction:', err);
    next();
  }
};

// Middleware to check if user is authenticated
const isAuthenticated = (req: Request, res: Response, next: Function) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Unauthorized" });
};

// Middleware to check if user is admin
const isAdmin = (req: Request, res: Response, next: Function) => {
  if (req.isAuthenticated() && (req.user?.isAdmin || req.user?.isOwner)) {
    return next();
  }
  res.status(403).json({ message: "Forbidden" });
};

// Middleware to check if user is owner (krane)
const isOwner = (req: Request, res: Response, next: Function) => {
  if (req.isAuthenticated() && req.user?.isOwner) {
    return next();
  }
  res.status(403).json({ message: "Forbidden - Owner only" });
};

const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storageMulter = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storageMulter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.'));
    }
  }
});

// Store active WebSocket connections
const activeConnections: Map<number, WebSocket> = new Map();

// Send notification to all connected users
const notifyAllUsers = (message: any) => {
  activeConnections.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    }
  });
};

// Send announcement to all connected users
const broadcastAnnouncement = (announcement: any, adminName: string) => {
  notifyAllUsers({
    type: 'system_announcement',
    message: `New announcement: ${announcement.title}`,
    announcementId: announcement.id,
    authorName: adminName,
    important: announcement.important
  });
};

export async function registerRoutes(app: Express): Promise<Server> {
  // Apply IP restriction middleware to all routes
  app.use(checkIPRestriction);

  // Setup authentication routes
  setupAuth(app);

  // API endpoint to inform about IP restriction
  app.get("/api/restricted", (req, res) => {
    res.status(403).json({
      error: 'IP_RESTRICTED',
      message: 'Your IP address has been restricted from accessing this site.'
    });
  });

  // Search pastes by title
  app.get("/api/pastes/search", async (req, res) => {
    try {
      const query = req.query.q as string;

      if (!query) {
        return res.status(400).json({ message: "Search query is required" });
      }

      const pastes = await storage.searchPastesByTitle(query);
      res.json(pastes);
    } catch (err) {
      res.status(500).json({ message: "Error searching pastes" });
    }
  });

  // Paste routes
  app.get("/api/pastes", async (req, res) => {
    try {
      const pastes = await storage.getPublicPastes();

      // Sort pastes: pinned admin pastes first, then by creation date
      pastes.sort((a, b) => {
        // Check if paste is pinned (pinnedUntil time is in the future)
        const aIsPinned = a.isPinned && a.pinnedUntil && new Date(a.pinnedUntil) > new Date();
        const bIsPinned = b.isPinned && b.pinnedUntil && new Date(b.pinnedUntil) > new Date();

        // First sort by pinned status
        if (aIsPinned && !bIsPinned) return -1;
        if (!aIsPinned && bIsPinned) return 1;

        // Then sort by creation date (newest first)
        return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
      });

      res.json(pastes);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving pastes" });
    }
  });

  // IP Restriction Admin Routes

  // Get all restricted IPs
  app.get("/api/admin/ip-restrictions", isAdmin, async (req, res) => {
    try {
      const restrictedIPs = await storage.getAllRestrictedIPs();
      res.json(restrictedIPs);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving IP restrictions" });
    }
  });

  // Add IP restriction
  app.post("/api/admin/ip-restrictions", isAdmin, async (req, res) => {
    try {
      const { ip, reason } = req.body;

      if (!ip || !reason) {
        return res.status(400).json({ message: "IP address and reason are required" });
      }

      // Simple IP validation
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (!ipRegex.test(ip)) {
        return res.status(400).json({ message: "Invalid IP address format" });
      }

      // Don't allow restricting your own IP
      const userIP = req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '';
      if (ip === userIP) {
        return res.status(400).json({ message: "You cannot restrict your own IP address" });
      }

      await storage.addRestrictedIP(ip, reason, req.user!.id);

      res.status(201).json({ message: "IP restricted successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error adding IP restriction" });
    }
  });

  // Remove IP restriction
  app.delete("/api/admin/ip-restrictions/:ip", isAdmin, async (req, res) => {
    try {
      const ip = req.params.ip;

      const success = await storage.removeRestrictedIP(ip);
      if (!success) {
        return res.status(404).json({ message: "IP restriction not found" });
      }

      res.status(200).json({ message: "IP restriction removed successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error removing IP restriction" });
    }
  });

  app.get("/api/pastes/clown", async (req, res) => {
    try {
      const pastes = await storage.getClownPastes();
      res.json(pastes);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving clown pastes" });
    }
  });

  app.get("/api/pastes/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid paste ID" });
      }

      const paste = await storage.getPaste(id);
      if (!paste) {
        return res.status(404).json({ message: "Paste not found" });
      }

      // All pastes are now public

      res.json(paste);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving paste" });
    }
  });

  app.post("/api/pastes", isAuthenticated, async (req, res) => {
    try {
      const pasteData = insertPasteSchema.parse(req.body);

      // Handle admin paste specific fields
      let adminPasteData = {};
      if (req.user!.isAdmin) {
        // If user is admin and requested admin paste features
        if (pasteData.isAdminPaste) {
          // Set admin paste fields
          adminPasteData = {
            isAdminPaste: true,
            isPinned: pasteData.isPinned || false,
            extraDetails: pasteData.extraDetails || '',
          };

          // If paste should be pinned, set pinnedUntil to 24 hours from now
          if (pasteData.isPinned) {
            const pinnedUntil = new Date();
            pinnedUntil.setHours(pinnedUntil.getHours() + 24);
            adminPasteData = {
              ...adminPasteData,
              pinnedUntil,
            };
          }
        }
      }

      const paste = await storage.createPaste({
        ...pasteData,
        userId: req.user!.id,
        ...adminPasteData,
      });

      // Notify all users if it's an admin paste
      if (req.user!.isAdmin && pasteData.isAdminPaste) {
        notifyAllUsers({
          type: 'admin_paste',
          message: `New admin paste: ${paste.title}`,
          pasteId: paste.id,
          authorName: req.user!.username
        });
      }

      res.status(201).json(paste);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid paste data", errors: err.errors });
      }
      res.status(500).json({ message: "Error creating paste" });
    }
  });

  // New endpoint: Update paste
  app.patch("/api/pastes/:id", isAuthenticated, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid paste ID" });
      }

      const paste = await storage.getPaste(id);
      if (!paste) {
        return res.status(404).json({ message: "Paste not found" });
      }

      // Only the paste owner or admin can edit
      if (req.user!.id !== paste.userId && !req.user!.isAdmin) {
        return res.status(403).json({ message: "You don't have permission to edit this paste" });
      }

      const updatedPaste = await storage.updatePaste(id, req.body);
      res.json(updatedPaste);
    } catch (err) {
      res.status(500).json({ message: "Error updating paste" });
    }
  });

  app.delete("/api/pastes/:id", isAuthenticated, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid paste ID" });
      }

      const paste = await storage.getPaste(id);
      if (!paste) {
        return res.status(404).json({ message: "Paste not found" });
      }

      // Only the paste owner or admin can delete
      if (req.user!.id !== paste.userId && !req.user!.isAdmin) {
        return res.status(403).json({ message: "You don't have permission to delete this paste" });
      }

      await storage.deletePaste(id);
      res.status(200).json({ message: "Paste deleted successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error deleting paste" });
    }
  });

  // User-specific paste routes
  app.get("/api/user/pastes", isAuthenticated, async (req, res) => {
    try {
      const pastes = await storage.getUserPastes(req.user!.id);
      res.json(pastes);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving user pastes" });
    }
  });

  // New endpoint: Get user profile
  app.get("/api/users/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      const user = await storage.getUser(id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Don't send the password back to the client
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving user" });
    }
  });

  // New endpoint: Get user's pastes
  app.get("/api/users/:id/pastes", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      const pastes = await storage.getUserPastes(id);
      // All pastes are public, no filtering needed
      const filteredPastes = pastes;

      res.json(filteredPastes);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving user pastes" });
    }
  });

  // New endpoint: Update user bio
  app.patch("/api/users/:id/bio", isAuthenticated, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      // Only the user or admin can update the bio
      if (req.user!.id !== id && !req.user!.isAdmin) {
        return res.status(403).json({ message: "You don't have permission to update this user's bio" });
      }

      const { bio } = req.body;
      if (typeof bio !== 'string') {
        return res.status(400).json({ message: "Bio must be a string" });
      }

      const user = await storage.updateUser(id, { bio });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Don't send the password back to the client
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (err) {
      res.status(500).json({ message: "Error updating user bio" });
    }
  });

  // New endpoint: Update user role (admin only)
  app.patch("/api/admin/users/:id/role", isAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      // Validate the role update
      const result = updateRoleSchema.safeParse(req.body);
      if (!result.success) {
        return res.status(400).json({ message: "Invalid role", errors: result.error.errors });
      }

      const user = await storage.updateUser(id, { role: result.data.role });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Don't send the password back to the client
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (err) {
      res.status(500).json({ message: "Error updating user role" });
    }
  });

  // New endpoint: Get user profile comments
  app.get("/api/users/:id/comments", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      const comments = await storage.getProfileComments(id);
      res.json(comments);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving comments" });
    }
  });

  // New endpoint: Add comment to user profile - Removed authentication requirement
  app.post("/api/users/:id/comments", async (req, res) => {
    try {
      const profileUserId = parseInt(req.params.id);
      if (isNaN(profileUserId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      const commentData = insertCommentSchema.parse({
        ...req.body,
        profileUserId
      });

      // If user is not logged in, set userId to 0 (anonymous)
      const userId = req.user ? req.user.id : 0;

      const comment = await storage.createComment({
        ...commentData,
        userId
      });

      res.status(201).json(comment);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid comment data", errors: err.errors });
      }
      res.status(500).json({ message: "Error creating comment" });
    }
  });

  // New endpoint: Delete comment
  app.delete("/api/comments/:id", isAuthenticated, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid comment ID" });
      }

      // Only allow deletion by admin (for moderation purposes)
      if (!req.user!.isAdmin) {
        return res.status(403).json({ message: "Only admins can delete comments" });
      }

      const success = await storage.deleteComment(id);
      if (!success) {
        return res.status(404).json({ message: "Comment not found" });
      }

      res.status(200).json({ message: "Comment deleted successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error deleting comment" });
    }
  });

  // Admin routes
  app.get("/api/admin/users", isAdmin, async (req, res) => {
    try {
      const users = await storage.getAllUsers();
      // Don't send passwords back to the client
      const usersWithoutPasswords = users.map(user => {
        const { password, ...userWithoutPassword } = user;
        return userWithoutPassword;
      });
      res.json(usersWithoutPasswords);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving users" });
    }
  });

  // New endpoint: Get all users (public)
  app.get("/api/users", async (req, res) => {
    try {
      const users = await storage.getAllUsers();
      // Only send public information
      const publicUsers = users.map(user => ({
        id: user.id,
        username: user.username,
        bio: user.bio,
        isAdmin: user.isAdmin,
        createdAt: user.createdAt
      }));
      res.json(publicUsers);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving users" });
    }
  });


  app.delete("/api/admin/users/:id", isAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      // Don't allow deleting yourself
      if (id === req.user!.id) {
        return res.status(400).json({ message: "Cannot delete your own account" });
      }

      const success = await storage.deleteUser(id);
      if (!success) {
        return res.status(404).json({ message: "User not found" });
      }

      res.status(200).json({ message: "User deleted successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error deleting user" });
    }
  });

  app.patch("/api/admin/pastes/:id", isAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid paste ID" });
      }

      const paste = await storage.getPaste(id);
      if (!paste) {
        return res.status(404).json({ message: "Paste not found" });
      }

      const updatedPaste = await storage.updatePaste(id, req.body);
      res.json(updatedPaste);
    } catch (err) {
      res.status(500).json({ message: "Error updating paste" });
    }
  });

  // New endpoint: Upload avatar
  app.post("/api/users/:id/avatar", isAuthenticated, upload.single('avatar'), async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      // Only allow users to update their own avatar
      if (req.user!.id !== id) {
        return res.status(403).json({ message: "You don't have permission to update this user's avatar" });
      }

      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      const avatarUrl = `/uploads/${req.file.filename}`;
      const user = await storage.updateUser(id, { avatarUrl });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Don't send the password back to the client
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (err) {
      res.status(500).json({ message: "Error updating avatar" });
    }
  });

  // Audit Log Routes (admin only)
  app.get("/api/admin/audit-logs", isAdmin, async (req, res) => {
    try {
      const logs = await storage.getAuditLogs();
      res.json(logs);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving audit logs" });
    }
  });

  app.get("/api/admin/audit-logs/deleted-users", isAdmin, async (req, res) => {
    try {
      const logs = await storage.getDeletedUsers();
      res.json(logs);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving deleted users logs" });
    }
  });

  app.get("/api/admin/audit-logs/deleted-pastes", isAdmin, async (req, res) => {
    try {
      const logs = await storage.getDeletedPastes();
      res.json(logs);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving deleted pastes logs" });
    }
  });

  app.get("/api/admin/audit-logs/edits", isAdmin, async (req, res) => {
    try {
      const logs = await storage.getEditLogs();
      res.json(logs);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving edit logs" });
    }
  });

  app.get("/api/admin/audit-logs/user/:id", isAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      if (isNaN(userId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      const logs = await storage.getAuditLogsByUser(userId);
      res.json(logs);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving user audit logs" });
    }
  });

  app.get("/api/admin/audit-logs/action/:action", isAdmin, async (req, res) => {
    try {
      const action = req.params.action;
      const logs = await storage.getAuditLogsByAction(action);
      res.json(logs);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving action audit logs" });
    }
  });

  // Achievement routes
  app.get("/api/users/:id/achievements", isAuthenticated, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      if (isNaN(userId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      // Only allow users to view their own achievements or admin
      if (req.user!.id !== userId && !req.user!.isAdmin) {
        return res.status(403).json({ message: "Unauthorized" });
      }

      const achievements = await storage.getUserAchievements(userId);
      res.json(achievements);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving achievements" });
    }
  });

  app.post("/api/users/:id/achievements/mark-seen", isAuthenticated, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      if (isNaN(userId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      // Only allow users to mark their own achievements as seen
      if (req.user!.id !== userId) {
        return res.status(403).json({ message: "Unauthorized" });
      }

      await storage.markUserAchievementsSeen(userId);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ message: "Error marking achievements as seen" });
    }
  });

  // Follow system routes
  app.get("/api/users/:id/followers", async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      if (isNaN(userId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      const followers = await storage.getUserFollowers(userId);
      
      // If user is authenticated, add isFollowing flag to each follower
      if (req.isAuthenticated()) {
        const currentUserId = req.user!.id;
        const followingIds = await storage.getUserFollowingIds(currentUserId);
        
        const followersWithFollowingStatus = followers.map(follower => ({
          ...follower,
          isFollowing: followingIds.includes(follower.id)
        }));
        
        return res.json(followersWithFollowingStatus);
      }
      
      res.json(followers);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving followers" });
    }
  });

  app.get("/api/users/:id/following", async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      if (isNaN(userId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      const following = await storage.getUserFollowing(userId);
      
      // Always mark as following since this is the "following" list
      const followingWithStatus = following.map(user => ({
        ...user,
        isFollowing: true
      }));
      
      res.json(followingWithStatus);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving following" });
    }
  });

  app.post("/api/users/:id/follow", isAuthenticated, async (req, res) => {
    try {
      const followingId = parseInt(req.params.id);
      const followerId = req.user!.id;
      
      if (isNaN(followingId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      if (followerId === followingId) {
        return res.status(400).json({ message: "You cannot follow yourself" });
      }

      // Check if following user exists
      const followingUser = await storage.getUser(followingId);
      if (!followingUser) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if already following
      const isFollowing = await storage.isFollowing(followerId, followingId);
      if (isFollowing) {
        return res.status(400).json({ message: "Already following this user" });
      }

      await storage.createFollow(followerId, followingId);
      
      res.status(201).json({ message: "Now following user" });
    } catch (err) {
      res.status(500).json({ message: "Error following user" });
    }
  });

  app.delete("/api/users/:id/follow", isAuthenticated, async (req, res) => {
    try {
      const followingId = parseInt(req.params.id);
      const followerId = req.user!.id;
      
      if (isNaN(followingId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      // Check if currently following
      const isFollowing = await storage.isFollowing(followerId, followingId);
      if (!isFollowing) {
        return res.status(400).json({ message: "Not following this user" });
      }

      await storage.deleteFollow(followerId, followingId);
      
      res.status(200).json({ message: "Unfollowed user" });
    } catch (err) {
      res.status(500).json({ message: "Error unfollowing user" });
    }
  });

  // Export logs endpoint (owner only)
  // Announcement routes
  app.get("/api/announcements", async (req, res) => {
    try {
      const announcements = await storage.getActiveAnnouncements();
      res.json(announcements);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving announcements" });
    }
  });

  app.get("/api/announcements/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid announcement ID" });
      }

      const announcement = await storage.getAnnouncement(id);
      if (!announcement) {
        return res.status(404).json({ message: "Announcement not found" });
      }

      res.json(announcement);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving announcement" });
    }
  });

  app.post("/api/admin/announcements", isAdmin, async (req, res) => {
    try {
      const announcementData = insertAnnouncementSchema.parse(req.body);
      
      const announcement = await storage.createAnnouncement({
        ...announcementData,
        userId: req.user!.id
      });

      // Broadcast the announcement to all users
      broadcastAnnouncement(announcement, req.user!.username);
      
      // Log the action
      await storage.createAuditLog({
        action: "announcement_created",
        userId: req.user!.id,
        targetId: announcement.id,
        targetType: "announcement",
        details: JSON.stringify(announcement),
        ipAddress: req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || ''
      });

      res.status(201).json(announcement);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid announcement data", errors: err.errors });
      }
      res.status(500).json({ message: "Error creating announcement" });
    }
  });

  app.delete("/api/admin/announcements/:id", isAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid announcement ID" });
      }

      const success = await storage.deleteAnnouncement(id);
      if (!success) {
        return res.status(404).json({ message: "Announcement not found" });
      }

      // Log the action
      await storage.createAuditLog({
        action: "announcement_deleted",
        userId: req.user!.id,
        targetId: id,
        targetType: "announcement",
        ipAddress: req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || ''
      });

      res.status(200).json({ message: "Announcement deleted successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error deleting announcement" });
    }
  });

  app.get("/api/admin/export-logs", isOwner, async (req, res) => {
    try {
      // Get format from query parameter, default to csv
      const format = (req.query.format as string)?.toLowerCase() || 'csv';

      // Get all logs from storage
      const auditLogs = await storage.getAuditLogs();
      
      // Format logs for export
      const logsForExport = auditLogs.map(log => {
        // Parse JSON details if they exist
        let detailsStr = '';
        try {
          if (log.details) {
            const detailsObj = JSON.parse(log.details);
            detailsStr = JSON.stringify(detailsObj);
          }
        } catch (e) {
          detailsStr = log.details || '';
        }

        return {
          id: log.id,
          action: log.action,
          userId: log.userId,
          targetId: log.targetId || '',
          targetType: log.targetType || '',
          details: detailsStr,
          ipAddress: log.ipAddress || '',
          timestamp: log.createdAt,
          formattedDate: new Date(log.createdAt).toLocaleString()
        };
      });

      if (format === 'json') {
        // Set headers for JSON file download
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="doxnightmare-logs-${Date.now()}.json"`);
        
        // Send logs as downloadable JSON file
        return res.json({
          exportDate: new Date().toISOString(),
          totalLogs: logsForExport.length,
          logs: logsForExport
        });
      } else {
        // CSV format
        // Create CSV header
        let csvContent = 'ID,Action,User ID,Target ID,Target Type,Details,IP Address,Timestamp,Formatted Date\n';
        
        // Add each log as a CSV row
        logsForExport.forEach(log => {
          // Escape fields that might contain commas
          const escapeCsv = (field: any) => {
            const str = String(field || '');
            return str.includes(',') ? `"${str.replace(/"/g, '""')}"` : str;
          };
          
          csvContent += [
            log.id,
            escapeCsv(log.action),
            log.userId,
            escapeCsv(log.targetId),
            escapeCsv(log.targetType),
            escapeCsv(log.details),
            escapeCsv(log.ipAddress),
            log.timestamp,
            escapeCsv(log.formattedDate)
          ].join(',') + '\n';
        });
        
        // Set headers for CSV file download
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="doxnightmare-logs-${Date.now()}.csv"`);
        
        // Send CSV content
        return res.send(csvContent);
      }
    } catch (err) {
      console.error("Error exporting logs:", err);
      res.status(500).json({ message: "Error exporting logs" });
    }
  });

  // OWNER-ONLY ROUTES - Special privileges for krane

  // Make users admin
  app.post("/api/owner/promote-admin", isOwner, async (req, res) => {
    try {
      const { userId } = req.body;
      
      if (!userId) {
        return res.status(400).json({ message: "User ID is required" });
      }

      const user = await storage.updateUser(userId, { isAdmin: true });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Don't send the password back to the client
      const { password, ...userWithoutPassword } = user;
      
      // Log the action
      await storage.createAuditLog({
        action: "owner_promoted_admin",
        userId: req.user!.id,
        targetId: userId,
        targetType: "user",
        details: JSON.stringify({ promotedBy: req.user!.username }),
        ipAddress: req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '',
      });

      res.json({ 
        message: "User promoted to admin successfully", 
        user: userWithoutPassword 
      });
    } catch (err) {
      res.status(500).json({ message: "Error promoting user to admin" });
    }
  });

  // Remove admin status
  app.post("/api/owner/demote-admin", isOwner, async (req, res) => {
    try {
      const { userId } = req.body;
      
      if (!userId) {
        return res.status(400).json({ message: "User ID is required" });
      }

      const user = await storage.updateUser(userId, { isAdmin: false });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Don't send the password back to the client
      const { password, ...userWithoutPassword } = user;
      
      // Log the action
      await storage.createAuditLog({
        action: "owner_demoted_admin",
        userId: req.user!.id,
        targetId: userId,
        targetType: "user",
        details: JSON.stringify({ demotedBy: req.user!.username }),
        ipAddress: req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '',
      });

      res.json({ 
        message: "Admin status removed successfully", 
        user: userWithoutPassword 
      });
    } catch (err) {
      res.status(500).json({ message: "Error removing admin status" });
    }
  });

  // Assign moderator role
  app.post("/api/owner/add-moderator", isOwner, async (req, res) => {
    try {
      const { userId } = req.body;
      
      if (!userId) {
        return res.status(400).json({ message: "User ID is required" });
      }

      const user = await storage.updateUser(userId, { role: "moderator" });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Don't send the password back to the client
      const { password, ...userWithoutPassword } = user;
      
      // Log the action
      await storage.createAuditLog({
        action: "owner_added_moderator",
        userId: req.user!.id,
        targetId: userId,
        targetType: "user",
        details: JSON.stringify({ addedBy: req.user!.username }),
        ipAddress: req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '',
      });

      res.json({ 
        message: "User promoted to moderator successfully", 
        user: userWithoutPassword 
      });
    } catch (err) {
      res.status(500).json({ message: "Error promoting user to moderator" });
    }
  });

  // Impersonate user (login as any user)
  app.post("/api/owner/impersonate", isOwner, async (req, res) => {
    try {
      const { userId } = req.body;
      
      if (!userId) {
        return res.status(400).json({ message: "User ID is required" });
      }

      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Log the impersonation
      await storage.createAuditLog({
        action: "owner_impersonated_user",
        userId: req.user!.id,
        targetId: userId,
        targetType: "user",
        details: JSON.stringify({ 
          impersonatedUsername: user.username,
          impersonatedBy: req.user!.username
        }),
        ipAddress: req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '',
      });

      // Don't send the password back to the client
      const { password, ...userWithoutPassword } = user;
      
      // Return impersonation token and user info
      res.json({
        message: "Impersonation successful",
        user: userWithoutPassword,
        impersonationInfo: {
          originalUserId: req.user!.id,
          impersonatedUserId: userId,
          timestamp: new Date().toISOString()
        }
      });
    } catch (err) {
      res.status(500).json({ message: "Error impersonating user" });
    }
  });

  // Get detailed user IP information
  app.get("/api/owner/user-ip-details/:userId", isOwner, async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      if (isNaN(userId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      // Get the user first
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Get all IP addresses associated with this user
      const ipHistory = await storage.getUserIPHistory(userId);
      
      // Log this sensitive access
      await storage.createAuditLog({
        action: "owner_accessed_ip_details",
        userId: req.user!.id,
        targetId: userId,
        targetType: "user_ip",
        details: JSON.stringify({ 
          accessedUsername: user.username,
          accessedBy: req.user!.username,
          ipCount: ipHistory.length
        }),
        ipAddress: req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '',
      });

      res.json({
        user: {
          id: user.id,
          username: user.username,
          currentIp: user.ipAddress
        },
        ipHistory: ipHistory
      });
    } catch (err) {
      res.status(500).json({ message: "Error retrieving IP details" });
    }
  });

  // Get all IP restrictions with detailed info
  app.get("/api/owner/ip-restrictions/detailed", isOwner, async (req, res) => {
    try {
      const restrictedIPs = await storage.getAllRestrictedIPsDetailed();
      res.json(restrictedIPs);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving detailed IP restrictions" });
    }
  });

  // System-wide settings management
  app.get("/api/owner/system-settings", isOwner, async (req, res) => {
    try {
      const settings = await storage.getSystemSettings();
      res.json(settings);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving system settings" });
    }
  });

  app.post("/api/owner/system-settings", isOwner, async (req, res) => {
    try {
      const settings = req.body;
      await storage.updateSystemSettings(settings);
      
      // Log this action
      await storage.createAuditLog({
        action: "owner_updated_system_settings",
        userId: req.user!.id,
        targetType: "system",
        details: JSON.stringify({ 
          updatedBy: req.user!.username,
          settings: settings
        }),
        ipAddress: req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '',
      });
      
      res.json({ message: "System settings updated successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error updating system settings" });
    }
  });

  // View all user sessions
  app.get("/api/owner/active-sessions", isOwner, async (req, res) => {
    try {
      const sessions = await storage.getAllActiveSessions();
      res.json(sessions);
    } catch (err) {
      res.status(500).json({ message: "Error retrieving active sessions" });
    }
  });

  // Force logout a user by destroying their session
  app.delete("/api/owner/sessions/:sessionId", isOwner, async (req, res) => {
    try {
      const sessionId = req.params.sessionId;
      await storage.destroySession(sessionId);
      
      // Log this action
      await storage.createAuditLog({
        action: "owner_forced_logout",
        userId: req.user!.id,
        targetType: "session",
        details: JSON.stringify({ 
          sessionId: sessionId,
          actionBy: req.user!.username
        }),
        ipAddress: req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '',
      });
      
      res.json({ message: "User session terminated successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error terminating user session" });
    }
  });

  app.use('/uploads', express.static(uploadDir));

  const httpServer = createServer(app);

  // Set up WebSocket server
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', (ws, req) => {
    // Assign a temporary ID if the user is not authenticated
    let userId = 0;

    // Extract real IP address from request
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;

    // Set up message handler
    ws.on('message', async (message) => {
      try {
        const data = JSON.parse(message.toString());

        // Authenticate the WebSocket connection if token provided
        if (data.type === 'auth' && data.userId) {
          userId = parseInt(data.userId);
          // Store the connection
          activeConnections.set(userId, ws);
        }
      } catch (err) {
        console.error('Error processing WebSocket message:', err);
      }
    });

    // Clean up on disconnect
    ws.on('close', () => {
      if (userId > 0) {
        activeConnections.delete(userId);
      }
    });

    // Send initial connection acknowledgment
    ws.send(JSON.stringify({ type: 'connection', status: 'connected', message: 'Welcome to Pastebin!' }));
  });

  return httpServer;
}