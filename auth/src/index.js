module.exports = createAuthDirective;

const ALL = `ALL`;

const { defaultFieldResolver } = require(`graphql`);
const { SchemaDirectiveVisitor } = require(`apollo-server`);

function createAuthDirective({
    authorizeRequest,
    authorizeResponse,
    allRole = ALL
}) {
    return class AuthDirective extends SchemaDirectiveVisitor {
        visitObject(object) {
            const fields = object.getFields();
            Object.keys(fields).forEach(field => processField(fields[field], this.args));
        }
        visitFieldDefinition(field) {
            processField(field, this.args);
        }
    };

    function processField(field, args) {
        const { resolve = defaultFieldResolver } = field;
        const hasRoles = field.roles;
        field.roles = () => ({
            allow: args.allow || [],
            deny: args.deny || []
        });

        // We pass the field in so we can define the roles on it
        if (!hasRoles) {
            field.resolve = fieldAuthWrap(field, resolve);
        }
    }

    function fieldAuthWrap(field, next) {
        return async function authorizedResolve(source, args, context, info) {
            await validateRequest({ source, args, context, info });
            const response = await next(source, args, context, info);
            await validateResponse({ source, args, context, info, response });
            return response;
        };

        async function validateRequest({ source, args, context, info }) {
            return validate(({
                source,
                args,
                context,
                info,
                type: `request`,
                validation: authorizeRequest
            }));
        }

        function validateResponse({ source, args, context, info, response }) {
            return validate(({
                source,
                args,
                context,
                info,
                response,
                type: `response`,
                validation: authorizeResponse
            }));
        }

        async function validate({ type, source, args, context, info, validation, response }) {
            const roleData = typeof field.roles === `function` && field.roles();

            if (!roleData) {
                throw new Error(`Unable to authorize ${type}. Role data is missing from field`);
            }
            if (!roleData.allow.length) {
                throw new Error(`Unable to authorize ${type}. No allow role information defined, ` +
                    `therefore all are denied`);
            }

            if (roleData.deny.includes(allRole)) {
                throw new Error(`Unable to authorize ${type}. Authorization has been set to deny ${allRole}`);
            }

            const deniedRoles = (await Promise.all(roleData.deny.map(hasRole)))
                .filter(role => role);

            if (deniedRoles.length) {
                throw new Error(`Unable to authorize ${type}. Authorization has been set to deny ${allRole}, ` +
                    `and the request context has "${deniedRoles}"`);
            }

            // Allow pass through if allRole is defined
            if (roleData.allow.includes(allRole)) {
                return;
            }

            const allowedRoles = (await Promise.all(roleData.allow.map(hasRole)))
                .filter(role => role);

            if (allowedRoles.length) {
                return;
            }

            throw new Error(`Unable to authorize ${type}. Request context does not have any ` +
                `of the allowed roles (${roleData.allow.join(`, `)})`);

            async function hasRole(role) {
                const has = await validation({
                    role,
                    args,
                    info,
                    source,
                    context,
                    response
                });
                return has && role;
            }
        }
    }
}
