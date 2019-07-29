module.exports = createAuthDirective;

const ALL = `ALL`;

const { defaultFieldResolver } = require(`graphql`);
const { SchemaDirectiveVisitor } = require(`apollo-server`);

function createAuthDirective(requestHasRole, allRole = ALL) {
    const self = this;
    return class AuthDirective extends SchemaDirectiveVisitor {
        visitObject(object) {
            const fields = object.getFields();
            Object.keys(fields).forEach(field => processField(fields[field]));
        }
        visitFieldDefinition(field) {
            processField(field);
        }
    };

    function processField(field) {
        const { resolve = defaultFieldResolver } = field;
        const hasRoles = field.roles;
        field.roles = () => ({
            allow: self.args.allow || [],
            deny: self.args.deny || []
        });

        // We pass the field in so we can define the roles on it
        if (!hasRoles) {
            field.resolve = fieldAuthWrap(field, resolve);
        }
    }

    function fieldAuthWrap(field, next) {
        return async function authorizedResolve(source, args, context, info) {
            const roleData = typeof field.roles === `function` && field.roles();

            if (!roleData) {
                throw new Error(`Unable to authorize request. Role data is missing from field`);
            }
            if (!roleData.allow.length) {
                throw new Error(`Unable to authorize request. No allow role information defined, ` +
                    `therefore all requests are denied`);
            }

            if (roleData.deny.includes(allRole)) {
                throw new Error(`Unable to authorize request. Authorization has been set to deny ${allRole}`);
            }

            const deniedRoles = (await Promise.all(roleData.deny.map(hasRole)))
                .filter(role => role);

            if (deniedRoles.length) {
                throw new Error(`Unable to authorize request. Authorization has been set to deny ${allRole}, ` +
                    `and the request context has "${deniedRoles}"`);
            }

            // Allow pass through if allRole is defined
            if (roleData.allow.includes(allRole)) {
                return next(source, args, context, info);
            }

            const allowedRoles = (await Promise.all(roleData.allow.map(hasRole)))
                .filter(role => role);

            if (allowedRoles.length) {
                // TODO: Stats here?
                return next(source, args, context, info);
            }

            throw new Error(`Unable to authorize request. Request context does not have any ` +
                `of the allowed roles (${roleData.join(`, `)})`);

            async function hasRole(role) {
                const has = await requestHasRole({
                    role,
                    args,
                    info,
                    source,
                    context
                });
                return has && role;
            }
        };
    }
}
