package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rv-nath/rbac-rv/rbac"
)

var (
	pluginName        = "krakend-rbac"
	HandlerRegisterer = registerer(pluginName)
)

type registerer string

func (r registerer) RegisterHandlers(f func(
	name string,
	handler func(context.Context, map[string]interface{}, http.Handler) (http.Handler, error),
),
) {
	f(string(r), r.registerHandlers)
}

func (r registerer) registerHandlers(_ context.Context, extra map[string]interface{}, h http.Handler) (http.Handler, error) {
	// If the plugin requires some configuration, it should be under the name of the plugin. E.g.:
	/*
	   "extra_config":{
	       "plugin/http-server":{
	           "name":["krakend-server-example"],
	           "krakend-server-example":{
	               "path": "/some-path"
	           }
	       }
	   }
	*/

	// Initialize RBAC with the appropriate callbacks.
	rbacInstance := rbac.NewRBAC(fetchUserRoles, fetchRolePerms, fetchResources)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Executing plugin: ", pluginName)
		logger.Debug("Incoming request path: ", r.URL.Path)

		// Check if the bypassValidation field is available in the context
		if bypass, ok := r.Context().Value("bypassValidation").(bool); ok && bypass {
			logger.Debug("[PLUGIN: JWT Validator] Bypassing validation based on context flag")
			h.ServeHTTP(w, r)
			return
		}

		// Parse the intent from the request
		action, resource, resourceID, err := rbac.DetermineIntent(r.Method, r.URL.Path, fetchResources)
		if err != nil {
			logger.Error("Error determining intent:", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract user ID from headers or JWT (assuming JWT in headers for simplicity)
		userID := r.Header.Get("X-User-ID") // Adjust based on your authentication strategy
		if userID == "" {
			logger.Warning("Missing user ID in request")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if the user has permission to perform the action on the resource
		scope := "self" // Adjust based on the context or request data if needed
		if !rbacInstance.CheckPermission(userID, resourceID, resource, action, scope) {
			logger.Warning("Permission denied for user:", userID)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// If authorized, proceed with the request
		h.ServeHTTP(w, r)
	}), nil
}

func main() {}

// This logger is replaced by the RegisterLogger method to load the one from krakenD.
var logger Logger = noopLogger{}

func (registerer) RegisterLogger(v interface{}) {
	l, ok := v.(Logger)
	if !ok {
		return
	}
	logger = l
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Logger loaded", HandlerRegisterer))
}

type Logger interface {
	Debug(v ...interface{})
	Info(v ...interface{})
	Warning(v ...interface{})
	Error(v ...interface{})
	Critical(v ...interface{})
	Fatal(v ...interface{})
}

// Empty logger implementation
type noopLogger struct{}

func (n noopLogger) Debug(_ ...interface{})    {}
func (n noopLogger) Info(_ ...interface{})     {}
func (n noopLogger) Warning(_ ...interface{})  {}
func (n noopLogger) Error(_ ...interface{})    {}
func (n noopLogger) Critical(_ ...interface{}) {}
func (n noopLogger) Fatal(_ ...interface{})    {}

// Example callback functions for fetching roles and permissions
func fetchUserRoles(userID string) (rbac.UserRoles, error) {
	logger.Debug("Fetching roles for user: ", userID)
	// Implement the logic to fetch user roles from your backend
	// return rbac.UserRoles{Roles: []string{"admin"}}, nil
	// Define the query to get role names for the given userID
	query := `
        SELECT rm.role_name
        FROM user_roles ur
        JOIN roles_master rm ON ur.role_id = rm.role_id
        WHERE ur.user_id = $1
    `

	rows, err := dbPool.Query(context.Background(), query, userID)
	if err != nil {
		return rbac.UserRoles{}, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var roleName string
		if err := rows.Scan(&roleName); err != nil {
			return rbac.UserRoles{}, fmt.Errorf("failed to scan row: %w", err)
		}
		roles = append(roles, roleName)
	}

	if rows.Err() != nil {
		return rbac.UserRoles{}, fmt.Errorf("error iterating rows: %w", rows.Err())
	}

	return rbac.UserRoles{Roles: roles}, nil
}

/*
call back fn for fetching resources list from backend db.
*/
func fetchResources() ([]string, error) {
	// Implement the logic to fetch resource names
	// return []string{"user", "order"}, nil
	logger.Debug("Fetching resources from database...")
	query := `SELECT name FROM resources_master`
	rows, err := dbPool.Query(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	var resources []string
	for rows.Next() {
		var resourceName string
		if err := rows.Scan(&resourceName); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		resources = append(resources, resourceName)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("error iterating rows: %w", rows.Err())
	}

	return resources, nil
}

func fetchRolePerms(roleID string) (rbac.RolePermissions, error) {
	logger.Debug("Fetching permissions for role: ", roleID)
	// Implement the logic to fetch role permissions from your backend
	// return rbac.RolePermissions{}, nil
	query := `
        SELECT 
            rm.name AS resource_name,
            pm.name AS permission_name,
            rrp.scope_id,
            true AS allowed
        FROM role_resource_permissions rrp
        JOIN resources_master rm ON rrp.resource_id = rm.id
        JOIN permissions_master pm ON rrp.permission_id = pm.id
        WHERE rrp.role_id = $1
    `

	rows, err := dbPool.Query(context.Background(), query, roleID)
	if err != nil {
		return rbac.RolePermissions{}, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	var permissions []rbac.Permission
	for rows.Next() {
		var resourceName, permissionName, scopeID string
		var allowed bool

		if err := rows.Scan(&resourceName, &permissionName, &scopeID, &allowed); err != nil {
			return rbac.RolePermissions{}, fmt.Errorf("failed to scan row: %w", err)
		}

		permissions = append(permissions, rbac.Permission{
			Resource:   resourceName,
			Permission: permissionName,
			Allowed:    allowed,
			Scope:      scopeID,
		})
	}

	if rows.Err() != nil {
		return rbac.RolePermissions{}, fmt.Errorf("error iterating rows: %w", rows.Err())
	}

	return rbac.RolePermissions{
		RoleID: roleID,
		Perms:  permissions,
	}, nil
}

// Global connection
var dbPool *pgxpool.Pool

func init() {
	var err error
	dbURL := os.Getenv("DATABASE_URL")
	logger.Debug("Connecting to database : {}...", dbURL)
	dbPool, err = pgxpool.New(context.Background(), dbURL)
	if err != nil {
		logger.Error("Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	logger.Info("Connected to database")
}
