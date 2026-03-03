package db

const (
	sqlGetStats = `
		SELECT
			(SELECT COUNT(*) FROM password_entries WHERE user_id = $1),
			(SELECT COUNT(*) FROM secure_notes WHERE user_id = $1),
			(SELECT COUNT(*) FROM groups WHERE user_id = $1),
			(SELECT COUNT(*) FROM tags WHERE user_id = $1),
			(SELECT COUNT(*) FROM import_issues)
	`

	sqlUpsertPassword = `
		INSERT INTO password_entries (id, user_id, title, username, password_enc, url, notes_enc, import_source, import_raw, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10, NOW()), COALESCE($11, NOW()))
		ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			title = EXCLUDED.title,
			username = EXCLUDED.username,
			password_enc = EXCLUDED.password_enc,
			url = EXCLUDED.url,
			notes_enc = EXCLUDED.notes_enc,
			import_source = EXCLUDED.import_source,
			import_raw = EXCLUDED.import_raw,
			updated_at = COALESCE($11, NOW())
	`

	sqlInsertEntryTag = `
		INSERT INTO entry_tags (entry_id, tag_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`

	sqlInsertGroupEntry = `
		INSERT INTO group_entries (group_id, entry_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`

	sqlListPasswords = `
		SELECT p.id, p.title, p.username, p.url,
			   COALESCE(string_agg(DISTINCT t.name, ','), '') AS tags,
			   COALESCE(string_agg(DISTINCT g.name, ','), '') AS groups
		FROM password_entries p
		LEFT JOIN entry_tags et ON et.entry_id = p.id
		LEFT JOIN tags t ON t.id = et.tag_id
		LEFT JOIN group_entries ge ON ge.entry_id = p.id
		LEFT JOIN groups g ON g.id = ge.group_id
		WHERE p.user_id = $1
		GROUP BY p.id
		ORDER BY p.updated_at DESC
	`

	sqlListPasswordIDs = `
		SELECT id FROM password_entries WHERE user_id = $1 ORDER BY updated_at DESC
	`

	sqlGetPassword = `
		SELECT p.id, p.user_id, p.title, p.username, p.password_enc, p.url, p.notes_enc,
			   p.import_source, p.import_raw,
			   COALESCE(string_agg(DISTINCT t.name, ','), '') AS tags,
			   COALESCE(string_agg(DISTINCT g.name, ','), '') AS groups
		FROM password_entries p
		LEFT JOIN entry_tags et ON et.entry_id = p.id
		LEFT JOIN tags t ON t.id = et.tag_id
		LEFT JOIN group_entries ge ON ge.entry_id = p.id
		LEFT JOIN groups g ON g.id = ge.group_id
		WHERE p.id = $1
		GROUP BY p.id
	`

	sqlUpdatePassword = `
		UPDATE password_entries
		SET title = $2, username = $3, password_enc = $4, url = $5, notes_enc = $6, updated_at = NOW()
		WHERE id = $1 AND user_id = $7
	`

	sqlDeleteEntryTagsByEntryID = `
		DELETE FROM entry_tags WHERE entry_id = $1
	`

	sqlDeleteGroupEntriesByEntryID = `
		DELETE FROM group_entries WHERE entry_id = $1
	`

	sqlDeletePassword = `
		DELETE FROM password_entries WHERE id = $1 AND user_id = $2
	`

	sqlUpsertSecureNote = `
		INSERT INTO secure_notes (id, user_id, title, body_enc, import_source, import_raw, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, NOW()), COALESCE($8, NOW()))
		ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			title = EXCLUDED.title,
			body_enc = EXCLUDED.body_enc,
			import_source = EXCLUDED.import_source,
			import_raw = EXCLUDED.import_raw,
			updated_at = COALESCE($8, NOW())
	`

	sqlListNotes = `
		SELECT id, title, updated_at
		FROM secure_notes
		WHERE user_id = $1
		ORDER BY updated_at DESC
	`

	sqlListTags = `
		SELECT t.id, t.name, COUNT(et.entry_id) AS count
		FROM tags t
		LEFT JOIN entry_tags et ON et.tag_id = t.id
		WHERE t.user_id = $1
		GROUP BY t.id
		ORDER BY t.name
	`

	sqlListGroups = `
		SELECT g.id, g.name, COUNT(ge.entry_id) AS count
		FROM groups g
		LEFT JOIN group_entries ge ON ge.group_id = g.id
		WHERE g.user_id = $1
		GROUP BY g.id
		ORDER BY g.name
	`

	sqlListNoteIDs = `
		SELECT id FROM secure_notes WHERE user_id = $1 ORDER BY updated_at DESC
	`

	sqlInsertImportRun = `
		INSERT INTO import_runs (
			id, user_id, filename, file_size, imported_passwords, imported_notes,
			existing_count, new_count, skipped_count
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`

	sqlListImportRuns = `
		SELECT id, user_id, filename, file_size, imported_passwords, imported_notes,
		       existing_count, new_count, skipped_count, created_at
		FROM import_runs
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	sqlInsertImportIssue = `
		INSERT INTO import_issues (id, import_run_id, source, type_name, title, external_uuid, reason, raw)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`

	sqlListImportIssues = `
		SELECT id, import_run_id, source, type_name, title, external_uuid, reason, raw, created_at
		FROM import_issues
		ORDER BY created_at DESC
		LIMIT $1
	`

	sqlCountUsers = `
		SELECT COUNT(*) FROM users
	`

	sqlCreateUser = `
		INSERT INTO users (id, email, password_hash, master_password_hash, is_admin)
		VALUES ($1, $2, $3, $4, $5)
	`

	sqlGetUserByEmail = `
		SELECT id, email, password_hash, master_password_hash, is_admin, created_at
		FROM users
		WHERE email = $1
	`

	sqlGetUserByID = `
		SELECT id, email, password_hash, master_password_hash, is_admin, created_at
		FROM users
		WHERE id = $1
	`

	sqlListUsers = `
		SELECT id, email, is_admin, created_at
		FROM users
		ORDER BY created_at ASC
	`

	sqlUpdateUserCredentials = `
		UPDATE users
		SET password_hash = COALESCE($2, password_hash),
		    master_password_hash = COALESCE($3, master_password_hash)
		WHERE id = $1
	`

	sqlCreateSession = `
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES ($1, $2, $3)
	`

	sqlGetSession = `
		SELECT id, user_id, created_at, expires_at
		FROM sessions
		WHERE id = $1
	`

	sqlDeleteSession = `
		DELETE FROM sessions WHERE id = $1
	`

	sqlAssignPasswordsToUser = `
		UPDATE password_entries SET user_id = $1 WHERE user_id IS NULL
	`

	sqlAssignNotesToUser = `
		UPDATE secure_notes SET user_id = $1 WHERE user_id IS NULL
	`

	sqlAssignTagsToUser = `
		UPDATE tags SET user_id = $1 WHERE user_id IS NULL
	`

	sqlAssignGroupsToUser = `
		UPDATE groups SET user_id = $1 WHERE user_id IS NULL
	`

	sqlGetNote = `
		SELECT id, user_id, title, body_enc, created_at, updated_at, import_source, import_raw
		FROM secure_notes
		WHERE id = $1
	`

	sqlUpdateNote = `
		UPDATE secure_notes
		SET title = $2, body_enc = $3, updated_at = NOW()
		WHERE id = $1 AND user_id = $4
	`

	sqlDeleteNote = `
		DELETE FROM secure_notes WHERE id = $1 AND user_id = $2
	`

	sqlExistsPassword = `
		SELECT EXISTS(SELECT 1 FROM password_entries WHERE id = $1 AND user_id = $2)
	`

	sqlExistsNote = `
		SELECT EXISTS(SELECT 1 FROM secure_notes WHERE id = $1 AND user_id = $2)
	`

	sqlEnsureTagInsert = `
		INSERT INTO tags (id, user_id, name)
		VALUES ($1, $2, $3)
		ON CONFLICT (name, user_id) DO NOTHING
	`

	sqlEnsureTagSelect = `
		SELECT id FROM tags WHERE name = $1 AND user_id = $2
	`

	sqlEnsureGroupInsert = `
		INSERT INTO groups (id, user_id, name)
		VALUES ($1, $2, $3)
		ON CONFLICT (name, user_id) DO NOTHING
	`

	sqlEnsureGroupSelect = `
		SELECT id FROM groups WHERE name = $1 AND user_id = $2
	`
)
