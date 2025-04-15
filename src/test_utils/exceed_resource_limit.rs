use crate::{
    RedisPool,
    constants::resource_limit::ResourceLimit,
    utils::incr_resource_limit::incr_resource_limit,
};

/// Exceeds the resource limit for the provided resource type and user ID (used only for tests).
///
/// * `redis_pool` - The Redis connection pool.
/// * `resource_limit` - The resource limit variant.
/// * `user_id` - The user ID value for the resource limit record.
pub async fn exceed_resource_limit(
    redis_pool: &RedisPool,
    resource_limit: ResourceLimit,
    user_id: i64,
) {
    for _ in 0..resource_limit.get_limit() + 1 {
        incr_resource_limit(redis_pool, resource_limit, user_id)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::RedisTestContext,
        utils::check_resource_limit::check_resource_limit,
    };
    use storiny_macros::test_context;

    mod serial {
        use super::*;

        #[test_context(RedisTestContext)]
        #[tokio::test]
        async fn can_exceed_resource_limit(ctx: &mut RedisTestContext) {
            let redis_pool = &ctx.redis_pool;
            exceed_resource_limit(redis_pool, ResourceLimit::CreateStory, 1_i64).await;

            let result = check_resource_limit(redis_pool, ResourceLimit::CreateStory, 1_i64)
                .await
                .unwrap();

            assert!(!result);
        }
    }
}
