package app

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/zain-23/local-vault/apps/server/internal/account"
	"github.com/zain-23/local-vault/apps/server/internal/audit"
	"github.com/zain-23/local-vault/apps/server/internal/auth"
	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
	"github.com/zain-23/local-vault/apps/server/internal/common/jwt"
	"github.com/zain-23/local-vault/apps/server/internal/common/middleware"
	"github.com/zain-23/local-vault/apps/server/internal/config"
	"github.com/zain-23/local-vault/apps/server/internal/dashboard"
	"github.com/zain-23/local-vault/apps/server/internal/device"
	"github.com/zain-23/local-vault/apps/server/internal/email"
	"github.com/zain-23/local-vault/apps/server/internal/events"
	"github.com/zain-23/local-vault/apps/server/internal/keys"
	"github.com/zain-23/local-vault/apps/server/internal/machine"
	"github.com/zain-23/local-vault/apps/server/internal/member"
	"github.com/zain-23/local-vault/apps/server/internal/vault"
	"github.com/zain-23/local-vault/apps/server/internal/workspace"
)

const serverVersion = "3.0.0"

// App holds the Fiber app and database — the single object main.go runs
type App struct {
	Fiber      *fiber.App
	DB         *mongo.Database
	Publisher  *email.Publisher
	JWTService *jwt.Service
}

// New connects to MongoDB, configures Fiber with middleware, and registers health endpoint
func New(cfg config.Config) (*App, error) {
	// --- MongoDB ---
	// ApplyURI parses connection string and configures connection pool, timeouts, etc.
	clientOpts := options.Client().ApplyURI(cfg.MongoURI)
	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel() // defer runs when function returns — frees timeout resources
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}
	log.Printf("✅ Connected to MongoDB: %s", cfg.MongoDB)

	// Select database — MongoDB creates it automatically on first write
	db := client.Database(cfg.MongoDB)

	// --------------- RabbitMQ (email + events) ---------
	// Optional in development so `go run` works without a broker.
	hub := events.NewHub()
	var publisher *email.Publisher
	var eventBus *events.Bus
	conn, mqCh, err := email.Connect(cfg.RabbitMQURL)
	if err != nil {
		if cfg.Env == "production" || cfg.Env == "prod" {
			return nil, err
		}
		log.Printf("⚠️ RabbitMQ unavailable (%v) — email + cross-instance events disabled", err)
		eventBus = events.NewLocalBus(hub)
	} else {
		if err := email.DeclareTopology(mqCh, cfg.EmailRetryDelay); err != nil {
			return nil, err
		}
		publisher = email.NewPublisher(mqCh)
		evCh, err := conn.Channel()
		if err != nil {
			log.Printf("⚠️ events channel: %v — using in-process bus", err)
			eventBus = events.NewLocalBus(hub)
		} else if bus, err := events.NewRabbitBus(hub, evCh); err != nil {
			log.Printf("⚠️ events bus: %v — using in-process bus", err)
			eventBus = events.NewLocalBus(hub)
		} else {
			eventBus = bus
		}
		log.Printf("✅ Connected to RabbitMQ")
	}

	// --- Fiber ---
	app := fiber.New(fiber.Config{
		// ErrorHandler runs when any handler returns an error — centralizes error responses
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// Check if error is our custom apperror type — if yes, use its status code
			if appErr, ok := errors.AsType[*apperror.Error](err); ok {
				return c.Status(appErr.Status).JSON(appErr.Body())
			}
			// Unknown error — send 500, don't leak internal details
			return c.Status(500).JSON(fiber.Map{"error": "internal server error"})
		},
	})

	// CORS — allows frontend (different port/domain) to call API, without this browser blocks requests
	app.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.CORSAllowedOrigins,
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Accept,Authorization,Content-Type,If-None-Match,Idempotency-Key,X-Device-ID",
		ExposeHeaders:    "ETag",
		AllowCredentials: true,
	}))

	// Logger — logs every request: method, path, status, duration
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${method} ${path} → ${status} (${latency})\n",
	}))

	// Health endpoint — no auth needed, used by monitoring/Docker to check if server is alive
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"version": serverVersion,
			"time":    time.Now(),
		})
	})

	// ------------ Wire Auth domain ----------
	// Create shared services first + authMW
	jwtService := jwt.NewService(cfg.JWTSecret, cfg.JWTAccessExpiry)
	authMW := middleware.Auth(jwtService)

	// Create auth domain: store -> service -> handler
	authStore := auth.NewStore(db)
	authService := auth.NewService(authStore, jwtService, cfg)
	authHandler := auth.NewHandler(authService, cfg)
	// OAuth
	oauthHandler := auth.NewOAuthHandler(authService, cfg)
	// Register all auth routes on the fiber app
	auth.RegisterRoutes(app, authHandler, oauthHandler, authMW)

	// ------------ Audit (built first — every domain records through it) ----------
	auditStore := audit.NewStore(db)
	auditService := audit.NewService(auditStore)

	// ------------ Wire Workspace domain ----------
	// workspace domain: store -> service -> handler
	wsStore := workspace.NewStore(db)
	wsService := workspace.NewService(wsStore, auditService)
	wsHandler := workspace.NewHandler(wsService)
	workspace.RegisterRoutes(app, wsHandler, wsStore, authMW)

	// ------------ Wire Member domain ----------
	memberStore := member.NewStore(db)
	memberService := member.NewService(memberStore, publisher, cfg, auditService)
	memberHandler := member.NewHandler(memberService)
	// store is passed too — RequireRole uses it to look up the caller's role.
	member.RegisterRoutes(app, memberHandler, memberStore, authMW)

	// ------------ Wire Device domain ----------
	// Depends on authService (mints the CLI's session — one source of truth for
	// tokens) and memberStore (verifies the approver belongs to the workspace).
	deviceStore := device.NewStore(db)
	deviceService := device.NewService(deviceStore, authService, cfg)
	deviceHandler := device.NewHandler(deviceService)
	device.RegisterRoutes(app, deviceHandler, authMW)

	// ------------ Wire Vault + account-keys domains ----------
	vaultStore := vault.NewStore(db)
	keysStore := keys.NewStore(db)
	vaultService := vault.NewService(vaultStore, auditService, memberDirectory{store: memberStore}, keyLookup{store: keysStore}, publisher, eventBus, cfg)
	keysService := keys.NewService(keysStore, keysDirectory{store: memberStore}, vaultService, auditService)
	keysHandler := keys.NewHandler(keysService)
	keys.RegisterRoutes(app, keysHandler, wsStore, authMW)
	vaultHandler := vault.NewHandler(vaultService, hub)
	vault.RegisterRoutes(app, vaultHandler, wsStore, authMW)

	machineStore := machine.NewStore(db)
	machineService := machine.NewService(machineStore, vaultService, jwtService, auditService, eventBus, cfg)
	machineHandler := machine.NewHandler(machineService, hub)
	machine.RegisterRoutes(app, machineHandler, wsStore, authMW, middleware.MachineAuth(jwtService))

	// ------------ Wire Audit domain (read side) ----------
	auditHandler := audit.NewHandler(auditService)
	audit.RegisterRoutes(app, auditHandler, wsStore, authMW)

	// ------------ Wire Dashboard domain ----------
	dashStore := dashboard.NewStore(db)
	dashService := dashboard.NewService(dashStore)
	dashHandler := dashboard.NewHandler(dashService)
	dashboard.RegisterRoutes(app, dashHandler, wsStore, authMW)

	// ------------ Wire Account domain ----------
	// Own store over the shared users/sessions collections; records account events.
	accountStore := account.NewStore(db)
	accountService := account.NewService(accountStore, auditService)
	accountHandler := account.NewHandler(accountService)
	account.RegisterRoutes(app, accountHandler, authMW)

	return &App{Fiber: app, DB: db, Publisher: publisher, JWTService: jwtService}, nil
}
