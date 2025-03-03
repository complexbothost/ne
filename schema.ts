import { pgTable, text, serial, integer, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Role type
export const UserRole = {
  RICH: "rich",
  FRAUD: "fraud",
  GANG: "gang",
} as const;

// Create a type from the object values
export type UserRole = (typeof UserRole)[keyof typeof UserRole];

// Audit Log Action Types
export const AuditLogAction = {
  USER_CREATED: "user_created",
  USER_DELETED: "user_deleted",
  USER_UPDATED: "user_updated",
  PASTE_CREATED: "paste_created",
  PASTE_DELETED: "paste_deleted",
  PASTE_UPDATED: "paste_updated",
  COMMENT_CREATED: "comment_created",
  COMMENT_DELETED: "comment_deleted",
  IP_RESTRICTED: "ip_restricted",
  IP_UNRESTRICTED: "ip_unrestricted",
  ROLE_UPDATED: "role_updated",
  SUGGESTION_CREATED: "suggestion_created",
  SUGGESTION_RESPONDED: "suggestion_responded",
} as const;

// Create a type from the object values
export type AuditLogAction = (typeof AuditLogAction)[keyof typeof AuditLogAction];

// User schema
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  ipAddress: text("ip_address"),
  bio: text("bio").default(""),
  avatarUrl: text("avatar_url"),
  bannerUrl: text("banner_url"),
  role: text("role"),
  isAdmin: boolean("is_admin").default(false).notNull(),
  isOwner: boolean("is_owner").default(false),
  notificationsEnabled: boolean("notifications_enabled").default(true).notNull(),
  adminNotificationsEnabled: boolean("admin_notifications_enabled").default(true).notNull(),
  lastPasteCreated: timestamp("last_paste_created"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
}).extend({
  notificationsEnabled: z.boolean().optional(),
  adminNotificationsEnabled: z.boolean().optional(),
  bannerUrl: z.string().optional(),
});

// User settings schema
export const updateSettingsSchema = z.object({
  bio: z.string().max(500, "Bio must be 500 characters or less").optional(),
  bannerUrl: z.string().url("Invalid banner URL").optional(),
  notificationsEnabled: z.boolean().optional(),
  adminNotificationsEnabled: z.boolean().optional(),
});

// IP-Account linkage
export const ipAccounts = pgTable("ip_accounts", {
  id: serial("id").primaryKey(),
  ipAddress: text("ip_address").notNull(),
  userId: integer("user_id").notNull(),
  firstSeen: timestamp("first_seen").defaultNow().notNull(),
  lastSeen: timestamp("last_seen").defaultNow().notNull(),
});

// Paste content search index
export const pasteSearchIndex = pgTable("paste_search_index", {
  id: serial("id").primaryKey(),
  pasteId: integer("paste_id").notNull(),
  content: text("content").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Paste schema
export const pastes = pgTable("pastes", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  content: text("content").notNull(),
  userId: integer("user_id").notNull(),
  isPrivate: boolean("is_private").default(false).notNull(),
  isHidden: boolean("is_hidden").default(false).notNull(),
  isClown: boolean("is_clown").default(false).notNull(),
  isAdminPaste: boolean("is_admin_paste").default(false).notNull(),
  isPinned: boolean("is_pinned").default(false),
  pinnedUntil: timestamp("pinned_until"),
  extraDetails: text("extra_details"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  lastEditedAt: timestamp("last_edited_at"),
  currentContent: text("current_content"),
});

// Paste version history
export const pasteVersions = pgTable("paste_versions", {
  id: serial("id").primaryKey(),
  pasteId: integer("paste_id").notNull(),
  title: text("title").notNull(),
  content: text("content").notNull(),
  message: text("message"), // Version/commit message
  userId: integer("user_id").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertPasteVersionSchema = createInsertSchema(pasteVersions).pick({
  pasteId: true,
  title: true,
  content: true,
  message: true,
});

// Paste favorites table
export const pasteFavorites = pgTable("paste_favorites", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  pasteId: integer("paste_id").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertPasteSchema = createInsertSchema(pastes).pick({
  title: true,
  content: true,
}).extend({
  isAdminPaste: z.boolean().optional(),
  isPinned: z.boolean().optional(),
  extraDetails: z.string().optional(),
});

// Comment schema
export const comments = pgTable("comments", {
  id: serial("id").primaryKey(),
  content: text("content").notNull(),
  userId: integer("user_id").notNull(),
  profileUserId: integer("profile_user_id").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertCommentSchema = createInsertSchema(comments).pick({
  content: true,
  profileUserId: true,
});

// Suggestion schema
export const suggestions = pgTable("suggestions", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  content: text("content").notNull(),
  userId: integer("user_id").notNull(),
  status: text("status").default("pending").notNull(),
  adminResponse: text("admin_response"),
  adminId: integer("admin_id"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const insertSuggestionSchema = createInsertSchema(suggestions).pick({
  title: true,
  content: true,
});

export const updateSuggestionResponseSchema = z.object({
  adminResponse: z.string().min(1, "Response cannot be empty"),
  status: z.enum(["pending", "approved", "rejected", "implemented"]),
});

// Audit Log schema
export const auditLogs = pgTable("audit_logs", {
  id: serial("id").primaryKey(),
  action: text("action").notNull(),
  userId: integer("user_id").notNull(),
  targetId: integer("target_id"),
  targetType: text("target_type"),
  details: text("details"),
  ipAddress: text("ip_address"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertAuditLogSchema = createInsertSchema(auditLogs).pick({
  action: true,
  userId: true,
  targetId: true,
  targetType: true,
  details: true,
  ipAddress: true,
});

// Types
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertPaste = z.infer<typeof insertPasteSchema>;
export type Paste = typeof pastes.$inferSelect;
export type InsertComment = z.infer<typeof insertCommentSchema>;
export type Comment = typeof comments.$inferSelect;
export type UpdateBio = z.infer<typeof updateBioSchema>;
export type UpdateRole = z.infer<typeof updateRoleSchema>;
export type InsertSuggestion = z.infer<typeof insertSuggestionSchema>;
export type UpdateSuggestionResponse = z.infer<typeof updateSuggestionResponseSchema>;
export type Suggestion = typeof suggestions.$inferSelect;
export type PasteFavorite = typeof pasteFavorites.$inferSelect;
export type InsertPasteFavorite = typeof pasteFavorites.$inferInsert;
export type UpdateSettings = z.infer<typeof updateSettingsSchema>;
export type IpAccount = typeof ipAccounts.$inferSelect;
export type PasteSearchIndex = typeof pasteSearchIndex.$inferSelect;
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;


export const updateBioSchema = z.object({
  bio: z.string().max(500, "Bio must be 500 characters or less"),
});

export const updateRoleSchema = z.object({
  role: z.enum([UserRole.RICH, UserRole.FRAUD, UserRole.GANG]).nullable(),
});

// Achievement system
export const achievementTypes = {
  FIRST_PASTE: "first_paste",
  POPULAR_PASTE: "popular_paste",
  CONTRIBUTOR: "contributor",
  COMMUNITY_MEMBER: "community_member",
  PROFILE_COMPLETE: "profile_complete",
} as const;

export type AchievementType = (typeof achievementTypes)[keyof typeof achievementTypes];

export const userAchievements = pgTable("user_achievements", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  achievementType: text("achievement_type").notNull(),
  earnedAt: timestamp("earned_at").defaultNow().notNull(),
  seen: boolean("seen").default(false).notNull(),
});

export type UserAchievement = typeof userAchievements.$inferSelect;


// User follows system
export const userFollows = pgTable("user_follows", {
  id: serial("id").primaryKey(),
  followerId: integer("follower_id").notNull(), 
  followingId: integer("following_id").notNull(), 
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export type UserFollow = typeof userFollows.$inferSelect;

// System announcements
export const announcements = pgTable("announcements", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  content: text("content").notNull(),
  userId: integer("user_id").notNull(), // Admin who created it
  important: boolean("important").default(false), // For critical announcements
  expiresAt: timestamp("expires_at"), // Optional expiration date
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertAnnouncementSchema = createInsertSchema(announcements).pick({
  title: true,
  content: true,
  important: true,
  expiresAt: true,
});

export type Announcement = typeof announcements.$inferSelect;
export type InsertAnnouncement = z.infer<typeof insertAnnouncementSchema>;

// Add new types for paste versions
export type PasteVersion = typeof pasteVersions.$inferSelect;
export type InsertPasteVersion = z.infer<typeof insertPasteVersionSchema>;