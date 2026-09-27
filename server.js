const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');

require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
    process.env.JWT_SECRET || 'dev-only-change-this-secret';

const ADMIN_USERNAME =
    process.env.ADMIN_USERNAME || '';

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD || '';

const DATABASE_URL =
    process.env.DATABASE_URL || '';

/* =========================================================
   OLD JSON FILE
   Used only for one-time migration
========================================================= */

const DATA_FILE =
    path.join(__dirname, 'data', 'customers.json');

fs.mkdirSync(path.dirname(DATA_FILE), {
    recursive: true
});

/* =========================================================
   POSTGRESQL
========================================================= */

if (!DATABASE_URL) {
    console.error('DATABASE_URL is not configured.');
    process.exit(1);
}

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

/* =========================================================
   APP SETTINGS
========================================================= */

app.use(cors());

app.use(express.json());

/* =========================================================
   DATABASE HELPERS
========================================================= */

function rowToCustomer(row) {
    if (!row) {
        return null;
    }

    return {
        id: row.id,
        name: row.name,
        email: row.email,
        username: row.username,
        passwordHash: row.password_hash,
        active: row.active,
        software: row.software,
        licenseKey: row.license_key,
        expiryDate: row.expiry_date,
        createdAt: row.created_at
            ? new Date(row.created_at).toISOString()
            : null,
        updatedAt: row.updated_at
            ? new Date(row.updated_at).toISOString()
            : null
    };
}

function publicCustomer(customer) {
    if (!customer) {
        return null;
    }

    const {
        passwordHash,
        ...safe
    } = customer;

    return safe;
}

function generateLicenseKey() {
    return 'DS-' +
        crypto
            .randomBytes(5)
            .toString('hex')
            .toUpperCase();
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS customers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            software TEXT NOT NULL DEFAULT 'Courier Billing Software',
            license_key TEXT NOT NULL,
            expiry_date DATE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ
        );
    `);

    await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS
        customers_email_lower_idx
        ON customers (LOWER(email));
    `);

    await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS
        customers_username_lower_idx
        ON customers (LOWER(username));
    `);

    await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS
        customers_license_key_idx
        ON customers (license_key);
    `);

    console.log('PostgreSQL database initialized.');
}

/* =========================================================
   ONE-TIME JSON MIGRATION
========================================================= */

function readOldCustomers() {

    try {

        if (!fs.existsSync(DATA_FILE)) {
            return [];
        }

        const data =
            fs.readFileSync(
                DATA_FILE,
                'utf8'
            );

        if (!data.trim()) {
            return [];
        }

        const customers =
            JSON.parse(data);

        return Array.isArray(customers)
            ? customers
            : [];

    } catch (error) {

        console.error(
            'Unable to read old customers.json:',
            error.message
        );

        return [];
    }
}

function safeDate(value) {

    if (!value) {
        return null;
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return null;
    }

    return date.toISOString();
}

async function migrateJsonCustomers() {

    const oldCustomers =
        readOldCustomers();

    if (!oldCustomers.length) {

        console.log(
            'No old customers.json data found.'
        );

        return;
    }

    console.log(
        `Found ${oldCustomers.length} old customer(s). Checking migration...`
    );

    for (const customer of oldCustomers) {

        try {

            if (
                !customer.id ||
                !customer.name ||
                !customer.email ||
                !customer.username ||
                !customer.passwordHash
            ) {

                console.log(
                    'Skipping incomplete customer:',
                    customer.username || customer.email
                );

                continue;
            }

            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM customers
                    WHERE LOWER(email) = LOWER($1)
                       OR LOWER(username) = LOWER($2)
                    LIMIT 1
                    `,
                    [
                        customer.email,
                        customer.username
                    ]
                );

            if (existing.rows.length) {

                console.log(
                    `Customer already exists: ${customer.username}`
                );

                continue;
            }

            await pool.query(
                `
                INSERT INTO customers (
                    id,
                    name,
                    email,
                    username,
                    password_hash,
                    active,
                    software,
                    license_key,
                    expiry_date,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    $6,
                    $7,
                    $8,
                    $9,
                    $10,
                    $11
                )
                `,
                [
                    String(customer.id),
                    customer.name,
                    customer.email,
                    customer.username,
                    customer.passwordHash,
                    customer.active !== false,
                    customer.software ||
                        'Courier Billing Software',
                    customer.licenseKey ||
                        generateLicenseKey(),
                    customer.expiryDate || null,
                    safeDate(customer.createdAt) ||
                        new Date().toISOString(),
                    safeDate(customer.updatedAt)
                ]
            );

            console.log(
                `Migrated customer: ${customer.username}`
            );

        } catch (error) {

            console.error(
                `Migration failed for ${customer.username}:`,
                error.message
            );
        }
    }

    console.log('JSON migration check completed.');
}

/* =========================================================
   HEALTH
========================================================= */

app.get('/api/health', async (req, res) => {

    try {

        await pool.query('SELECT 1');

        res.json({
            ok: true,
            service: 'DruvaSolution API',
            database: 'PostgreSQL'
        });

    } catch (error) {

        console.error(error);

        res.status(503).json({
            ok: false,
            service: 'DruvaSolution API',
            database: 'Unavailable'
        });
    }
});

/* =========================================================
   CUSTOMER LOGIN
========================================================= */

app.post('/api/login', async (req, res) => {

    try {

        const {
            username,
            password
        } = req.body;

        if (!username || !password) {

            return res.status(400).json({
                message:
                    'Username/email and password are required.'
            });
        }

        const result =
            await pool.query(
                `
                SELECT *
                FROM customers
                WHERE LOWER(email) = LOWER($1)
                   OR LOWER(username) = LOWER($1)
                LIMIT 1
                `,
                [username]
            );

        if (!result.rows.length) {

            return res.status(401).json({
                message:
                    'Invalid username/email or password.'
            });
        }

        const customer =
            rowToCustomer(result.rows[0]);

        if (!customer.active) {

            return res.status(403).json({
                message:
                    'Your customer account is inactive.'
            });
        }

        const passwordValid =
            await bcrypt.compare(
                password,
                customer.passwordHash
            );

        if (!passwordValid) {

            return res.status(401).json({
                message:
                    'Invalid username/email or password.'
            });
        }

        const token =
            jwt.sign(
                {
                    customerId:
                        customer.id,
                    role:
                        'customer'
                },
                JWT_SECRET,
                {
                    expiresIn: '8h'
                }
            );

        res.json({
            token,
            customer:
                publicCustomer(customer)
        });

    } catch (error) {

        console.error(
            'Customer login error:',
            error
        );

        res.status(500).json({
            message:
                'Login failed.'
        });
    }
});

/* =========================================================
   CUSTOMER AUTH
========================================================= */

function auth(req, res, next) {

    const header =
        req.headers.authorization || '';

    const token =
        header.startsWith('Bearer ')
            ? header.slice(7)
            : '';

    if (!token) {

        return res.status(401).json({
            message:
                'Login required.'
        });
    }

    try {

        req.user =
            jwt.verify(
                token,
                JWT_SECRET
            );

        next();

    } catch {

        res.status(401).json({
            message:
                'Session expired. Please login again.'
        });
    }
}

/* =========================================================
   CUSTOMER PROFILE
========================================================= */

app.get('/api/me', auth, async (req, res) => {

    try {

        const result =
            await pool.query(
                `
                SELECT *
                FROM customers
                WHERE id = $1
                LIMIT 1
                `,
                [req.user.customerId]
            );

        if (!result.rows.length) {

            return res.status(404).json({
                message:
                    'Customer not found.'
            });
        }

        const customer =
            rowToCustomer(result.rows[0]);

        if (!customer.active) {

            return res.status(403).json({
                message:
                    'Customer account is inactive.'
            });
        }

        res.json({
            customer:
                publicCustomer(customer)
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                'Unable to load customer profile.'
        });
    }
});

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post('/api/admin/login', (req, res) => {

    try {

        const {
            username,
            password
        } = req.body;

        if (
            !ADMIN_USERNAME ||
            !ADMIN_PASSWORD
        ) {

            return res.status(503).json({
                message:
                    'Admin credentials are not configured on the server.'
            });
        }

        if (
            username !== ADMIN_USERNAME ||
            password !== ADMIN_PASSWORD
        ) {

            return res.status(401).json({
                message:
                    'Invalid admin username or password.'
            });
        }

        const token =
            jwt.sign(
                {
                    role:
                        'admin',
                    username:
                        ADMIN_USERNAME
                },
                JWT_SECRET,
                {
                    expiresIn: '8h'
                }
            );

        res.json({
            token,
            admin: {
                username:
                    ADMIN_USERNAME,
                role:
                    'admin'
            }
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                'Admin login failed.'
        });
    }
});

/* =========================================================
   ADMIN AUTH
========================================================= */

function adminAuth(req, res, next) {

    const header =
        req.headers.authorization || '';

    const token =
        header.startsWith('Bearer ')
            ? header.slice(7)
            : '';

    if (!token) {

        return res.status(401).json({
            message:
                'Admin login required.'
        });
    }

    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        if (
            decoded.role !==
            'admin'
        ) {

            return res.status(403).json({
                message:
                    'Admin access required.'
            });
        }

        req.admin =
            decoded;

        next();

    } catch {

        return res.status(401).json({
            message:
                'Admin session expired.'
        });
    }
}

/* =========================================================
   ADMIN - CUSTOMER LIST
========================================================= */

app.get(
    '/api/admin/customers',
    adminAuth,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT *
                    FROM customers
                    ORDER BY created_at DESC
                    `
                );

            const customers =
                result.rows.map(row =>
                    publicCustomer(
                        rowToCustomer(row)
                    )
                );

            res.json({
                customers
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    'Unable to load customers.'
            });
        }
    }
);

/* =========================================================
   ADMIN - SINGLE CUSTOMER
========================================================= */

app.get(
    '/api/admin/customers/:id',
    adminAuth,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT *
                    FROM customers
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [req.params.id]
                );

            if (!result.rows.length) {

                return res.status(404).json({
                    message:
                        'Customer not found.'
                });
            }

            const customer =
                rowToCustomer(
                    result.rows[0]
                );

            res.json({
                customer:
                    publicCustomer(customer)
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    'Unable to load customer.'
            });
        }
    }
);

/* =========================================================
   ADMIN - ADD CUSTOMER
========================================================= */

app.post(
    '/api/admin/customers',
    adminAuth,
    async (req, res) => {

        try {

            const {
                name,
                email,
                username,
                password,
                software,
                licenseKey,
                expiryDate,
                active
            } = req.body;

            if (
                !name ||
                !email ||
                !username ||
                !password
            ) {

                return res.status(400).json({
                    message:
                        'Name, email, username and password are required.'
                });
            }

            if (password.length < 6) {

                return res.status(400).json({
                    message:
                        'Password must be at least 6 characters.'
                });
            }

            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM customers
                    WHERE LOWER(email) = LOWER($1)
                       OR LOWER(username) = LOWER($2)
                    LIMIT 1
                    `,
                    [
                        email,
                        username
                    ]
                );

            if (existing.rows.length) {

                return res.status(409).json({
                    message:
                        'Email or username already exists.'
                });
            }

            const id =
                Date.now().toString();

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const finalLicenseKey =
                licenseKey ||
                generateLicenseKey();

            const finalSoftware =
                software ||
                'Courier Billing Software';

            const finalExpiryDate =
                expiryDate ||
                '2027-12-31';

            const finalActive =
                active !== false;

            const result =
                await pool.query(
                    `
                    INSERT INTO customers (
                        id,
                        name,
                        email,
                        username,
                        password_hash,
                        active,
                        software,
                        license_key,
                        expiry_date,
                        created_at
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        $8,
                        $9,
                        NOW()
                    )
                    RETURNING *
                    `,
                    [
                        id,
                        name,
                        email,
                        username,
                        passwordHash,
                        finalActive,
                        finalSoftware,
                        finalLicenseKey,
                        finalExpiryDate
                    ]
                );

            const customer =
                rowToCustomer(
                    result.rows[0]
                );

            res.status(201).json({
                message:
                    'Customer created successfully.',
                customer:
                    publicCustomer(customer)
            });

        } catch (error) {

            console.error(
                'Create customer error:',
                error
            );

            if (
                error.code ===
                '23505'
            ) {

                return res.status(409).json({
                    message:
                        'Email, username or license key already exists.'
                });
            }

            res.status(500).json({
                message:
                    'Unable to create customer.'
            });
        }
    }
);

/* =========================================================
   ADMIN - UPDATE CUSTOMER
========================================================= */

app.put(
    '/api/admin/customers/:id',
    adminAuth,
    async (req, res) => {

        try {

            const {
                name,
                email,
                username,
                password,
                software,
                licenseKey,
                expiryDate,
                active
            } = req.body;

            const existingResult =
                await pool.query(
                    `
                    SELECT *
                    FROM customers
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [req.params.id]
                );

            if (!existingResult.rows.length) {

                return res.status(404).json({
                    message:
                        'Customer not found.'
                });
            }

            const existing =
                rowToCustomer(
                    existingResult.rows[0]
                );

            if (email) {

                const emailCheck =
                    await pool.query(
                        `
                        SELECT id
                        FROM customers
                        WHERE LOWER(email) = LOWER($1)
                          AND id <> $2
                        LIMIT 1
                        `,
                        [
                            email,
                            req.params.id
                        ]
                    );

                if (emailCheck.rows.length) {

                    return res.status(409).json({
                        message:
                            'Email already exists.'
                    });
                }
            }

            if (username) {

                const usernameCheck =
                    await pool.query(
                        `
                        SELECT id
                        FROM customers
                        WHERE LOWER(username) = LOWER($1)
                          AND id <> $2
                        LIMIT 1
                        `,
                        [
                            username,
                            req.params.id
                        ]
                    );

                if (usernameCheck.rows.length) {

                    return res.status(409).json({
                        message:
                            'Username already exists.'
                    });
                }
            }

            if (licenseKey) {

                const licenseCheck =
                    await pool.query(
                        `
                        SELECT id
                        FROM customers
                        WHERE license_key = $1
                          AND id <> $2
                        LIMIT 1
                        `,
                        [
                            licenseKey,
                            req.params.id
                        ]
                    );

                if (licenseCheck.rows.length) {

                    return res.status(409).json({
                        message:
                            'License key already exists.'
                    });
                }
            }

            let passwordHash =
                existing.passwordHash;

            if (password) {

                if (password.length < 6) {

                    return res.status(400).json({
                        message:
                            'Password must be at least 6 characters.'
                    });
                }

                passwordHash =
                    await bcrypt.hash(
                        password,
                        12
                    );
            }

            const updatedName =
                name !== undefined
                    ? name
                    : existing.name;

            const updatedEmail =
                email !== undefined
                    ? email
                    : existing.email;

            const updatedUsername =
                username !== undefined
                    ? username
                    : existing.username;

            const updatedSoftware =
                software !== undefined
                    ? software
                    : existing.software;

            const updatedLicenseKey =
                licenseKey !== undefined
                    ? licenseKey
                    : existing.licenseKey;

            const updatedExpiryDate =
                expiryDate !== undefined
                    ? expiryDate
                    : existing.expiryDate;

            const updatedActive =
                active !== undefined
                    ? active
                    : existing.active;

            const result =
                await pool.query(
                    `
                    UPDATE customers
                    SET
                        name = $1,
                        email = $2,
                        username = $3,
                        password_hash = $4,
                        active = $5,
                        software = $6,
                        license_key = $7,
                        expiry_date = $8,
                        updated_at = NOW()
                    WHERE id = $9
                    RETURNING *
                    `,
                    [
                        updatedName,
                        updatedEmail,
                        updatedUsername,
                        passwordHash,
                        updatedActive,
                        updatedSoftware,
                        updatedLicenseKey,
                        updatedExpiryDate,
                        req.params.id
                    ]
                );

            const customer =
                rowToCustomer(
                    result.rows[0]
                );

            res.json({
                message:
                    'Customer updated successfully.',
                customer:
                    publicCustomer(customer)
            });

        } catch (error) {

            console.error(
                'Update customer error:',
                error
            );

            if (
                error.code ===
                '23505'
            ) {

                return res.status(409).json({
                    message:
                        'Email, username or license key already exists.'
                });
            }

            res.status(500).json({
                message:
                    'Unable to update customer.'
            });
        }
    }
);

/* =========================================================
   ADMIN - DELETE CUSTOMER
========================================================= */

app.delete(
    '/api/admin/customers/:id',
    adminAuth,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM customers
                    WHERE id = $1
                    RETURNING id
                    `,
                    [req.params.id]
                );

            if (!result.rows.length) {

                return res.status(404).json({
                    message:
                        'Customer not found.'
                });
            }

            res.json({
                message:
                    'Customer deleted successfully.'
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    'Unable to delete customer.'
            });
        }
    }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {

    try {

        await initializeDatabase();

        /*
         * If the old customers.json still exists,
         * migrate its customers into PostgreSQL.
         */
        await migrateJsonCustomers();

        app.listen(
            PORT,
            () => {

                console.log(
                    `DruvaSolution API running on port ${PORT}`
                );

                console.log(
                    'Database: PostgreSQL'
                );
            }
        );

    } catch (error) {

        console.error(
            'Server startup failed:',
            error
        );

        process.exit(1);
    }
}

startServer();
