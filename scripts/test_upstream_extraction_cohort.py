"""Adversarial identity fixtures; run remotely, never evidence of Rust execution."""
import copy
import unittest
from upstream_extraction_cohort import prove_pr_identity


class PullRequestIdentityTests(unittest.TestCase):
    def setUp(self):
        self.head, self.base, self.merge = '1' * 40, '2' * 40, '3' * 40
        self.tree = '4' * 40
        self.event = {'pull_request': {
            'head': {'sha': self.head, 'ref': 'ci/upstream-develop-dy-fixture', 'repo': {'full_name': 'dyKiU/mdk'}},
            'base': {'sha': self.base, 'ref': 'master', 'repo': {'full_name': 'dyKiU/mdk'}},
        }}
        self.arguments = dict(event=self.event, repository='dyKiU/mdk', source=self.head,
            workflow_sha=self.merge, merge_parents=[self.base, self.head],
            head_tree=self.tree, merge_tree=self.tree, base_is_ancestor=True)

    def reject(self, **changes):
        arguments = dict(self.arguments, **changes)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            prove_pr_identity(**arguments)

    def test_exact_fork_head_merge_parents_and_identical_tree(self):
        proof = prove_pr_identity(**self.arguments)
        self.assertEqual(proof['checkout_head'], self.head)
        self.assertEqual(proof['workflow_merge'], self.merge)
        self.assertTrue(proof['synthetic_merge_tree_identical_to_head'])

    def test_wrong_repository_and_both_cross_fork_endpoints(self):
        self.reject(repository='marmot-protocol/mdk')
        for endpoint in ['head', 'base']:
            event = copy.deepcopy(self.event)
            event['pull_request'][endpoint]['repo']['full_name'] = 'another/mdk'
            self.reject(event=event)

    def test_checkout_must_equal_event_head(self):
        self.reject(source='5' * 40)

    def test_base_must_be_master_and_ancestor(self):
        event = copy.deepcopy(self.event)
        event['pull_request']['base']['ref'] = 'develop_dy'
        self.reject(event=event)
        self.reject(base_is_ancestor=False)
        self.reject(base_is_ancestor=1)

    def test_exact_parent_order_and_cardinality(self):
        for parents in [[self.head, self.base], [self.base],
                        [self.base, self.head, '5' * 40], [self.base, '6' * 40]]:
            self.reject(merge_parents=parents)

    def test_merge_sha_cannot_be_substituted_with_head_or_base(self):
        self.reject(workflow_sha=self.head)
        self.reject(workflow_sha=self.base)

    def test_different_effective_merge_tree_is_rejected(self):
        self.reject(merge_tree='5' * 40)

    def test_full_object_identities_required(self):
        for key in ['source', 'workflow_sha', 'head_tree', 'merge_tree']:
            for value in ['HEAD', '1' * 39, 'G' * 40, None]:
                self.reject(**{key: value})

    def test_absent_or_corrupt_event_is_rejected(self):
        self.reject(event={})
        event = copy.deepcopy(self.event)
        del event['pull_request']['head']['repo']
        self.reject(event=event)


if __name__ == '__main__': unittest.main()
