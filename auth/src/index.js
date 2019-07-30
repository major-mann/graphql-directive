module.exports = createAuthDirective;

const ALL = `ALL`;

const { defaultFieldResolver } = require(`graphql`);
const { SchemaDirectiveVisitor } = require(`apollo-server`);

function createAuthDirective({
    validateRole,
    authorizeRequest,
    authorizeResponse,
    allRole = ALL
}) {
    return class AuthDirective extends SchemaDirectiveVisitor {
        async visitObject(object) {
            const fields = object.getFields();
            await Promise.all(
                Object.keys(fields).map(
                    async field => processField(object, fields[field], this.args)
                )
            );
        }
        async visitFieldDefinition(field, object) {
            await processField(object, field, this.args);
        }
    };

    async function processField(object, field, args) {
        const combined = [...(args.allow || []), ...(args.deny || [])]
            .filter((ele, idx, arr) => arr.indexOf(ele) === idx);
        await validate(combined);

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

        async function validate(roles) {
            if (Array.isArray(roles)) {
                await Promise.all(roles.map(role => validateRole({
                    object,
                    field,
                    role,
                    allow: Boolean(args.allow && args.allow.includes(role)),
                    deny: Boolean(args.deny && args.deny.includes(role))
                })));
            }
        }
    }

    function fieldAuthWrap(field, next) {
        return async function authorizedResolve(source, args, context, info) {
            await validateRequest({ source, args, context, info, field });
            const response = await next(source, args, context, info);
            await validateResponse({ source, args, context, info, response, field });
            return response;
        };

        async function validateRequest({ source, args, context, info, object, field }) {
            return validate(({
                source,
                args,
                context,
                info,
                field,
                object,
                type: `request`,
                validation: authorizeRequest
            }));
        }

        function validateResponse({ source, args, context, info, response, object, field }) {
            return validate(({
                source,
                args,
                context,
                info,
                response,
                field,
                object,
                type: `response`,
                validation: authorizeResponse
            }));
        }

        async function validate({ type, source, args, context, info, validation, response, object, field }) {
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
                    field,
                    object,
                    source,
                    context,
                    response
                });
                return has && role;
            }
        }
    }
}
