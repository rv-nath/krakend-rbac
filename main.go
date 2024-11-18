package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

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

	// The config variable contains all the keys defined in the configuration.
	// If the key doesn't exist or is not a map, the plugin returns an error and the default handler.
	_, ok := extra[pluginName].(map[string]interface{})
	if !ok {
		return h, errors.New("configuration not found")
	}

	// Initialize RBAC with the appropriate callbacks.
	rbacInstance := rbac.NewRBAC(fetchUserRoles, fetchRolePerms, fetchResources)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Executing plugin: ", pluginName)
		logger.Debug("Incoming request path: ", r.URL.Path)

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
	// Implement the logic to fetch user roles from your backend
	return rbac.UserRoles{Roles: []string{"admin"}}, nil
}

func fetchResources() ([]string, error) {
	// Implement the logic to fetch resource names
	return []string{"user", "order"}, nil
}

func fetchRolePerms(roleID string) (rbac.RolePermissions, error) {
	// Implement the logic to fetch role permissions from your backend
	return rbac.RolePermissions{}, nil
}
