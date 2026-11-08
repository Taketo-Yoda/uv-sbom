use std::collections::{HashMap, HashSet, VecDeque};

/// BFS traversal starting from `seeds`, returning all transitively reachable package names.
pub(super) fn bfs_reachable(
    dep_map: &HashMap<String, Vec<String>>,
    seeds: Vec<String>,
) -> HashSet<String> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    for dep in seeds {
        if !visited.contains(&dep) {
            visited.insert(dep.clone());
            queue.push_back(dep);
        }
    }

    while let Some(current) = queue.pop_front() {
        if let Some(deps) = dep_map.get(&current) {
            for dep in deps {
                if !visited.contains(dep) {
                    visited.insert(dep.clone());
                    queue.push_back(dep.clone());
                }
            }
        }
    }

    visited
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bfs_reachable_empty_seeds_returns_empty() {
        let dep_map = HashMap::new();
        let result = bfs_reachable(&dep_map, vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_bfs_reachable_transitively_follows_chain() {
        let mut dep_map = HashMap::new();
        dep_map.insert("a".to_string(), vec!["b".to_string()]);
        dep_map.insert("b".to_string(), vec!["c".to_string()]);
        dep_map.insert("c".to_string(), vec![]);

        let result = bfs_reachable(&dep_map, vec!["a".to_string()]);
        assert_eq!(
            result,
            HashSet::from(["a".to_string(), "b".to_string(), "c".to_string()])
        );
    }

    #[test]
    fn test_bfs_reachable_handles_cycles_without_infinite_loop() {
        let mut dep_map = HashMap::new();
        dep_map.insert("a".to_string(), vec!["b".to_string()]);
        dep_map.insert("b".to_string(), vec!["a".to_string()]);

        let result = bfs_reachable(&dep_map, vec!["a".to_string()]);
        assert_eq!(result, HashSet::from(["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn test_bfs_reachable_seed_not_in_dep_map_is_still_visited() {
        let dep_map = HashMap::new();
        let result = bfs_reachable(&dep_map, vec!["orphan".to_string()]);
        assert_eq!(result, HashSet::from(["orphan".to_string()]));
    }

    #[test]
    fn test_bfs_reachable_duplicate_seeds_deduplicated() {
        let mut dep_map = HashMap::new();
        dep_map.insert("a".to_string(), vec![]);

        let result = bfs_reachable(&dep_map, vec!["a".to_string(), "a".to_string()]);
        assert_eq!(result, HashSet::from(["a".to_string()]));
    }
}
