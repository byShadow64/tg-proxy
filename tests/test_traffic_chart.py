import unittest

from ui.traffic_chart import TrafficHistory


class TrafficHistoryTest(unittest.TestCase):
    def test_initial_totals_do_not_invent_a_transfer_rate(self):
        history = TrafficHistory()
        self.assertEqual(history.sample(10000, 80000, 100), (0, 0))
        self.assertEqual(tuple(history.points), ((100, 0, 0),))

    def test_rates_use_actual_elapsed_time(self):
        history = TrafficHistory()
        history.sample(1000, 2000, 10)
        self.assertEqual(history.sample(3000, 10000, 12), (1000, 4000))

    def test_counter_reset_and_duplicate_timestamps_do_not_create_negative_or_infinite_rates(self):
        history = TrafficHistory()
        history.sample(1000, 2000, 10)
        self.assertEqual(history.sample(0, 0, 11), (0, 0))
        self.assertEqual(history.sample(100, 300, 11), (0, 0))
        self.assertEqual(len(history.points), 2)
        self.assertEqual(history.sample(100, 300, 12), (100, 300))

    def test_only_observed_samples_in_the_last_minute_are_kept(self):
        history = TrafficHistory()
        for second in range(121):
            history.sample(second * 100, second * 1000, second)
        self.assertEqual(history.points[0], (60, 100, 1000))
        self.assertEqual(history.points[-1], (120, 100, 1000))
        self.assertEqual(len(history.points), 61)


if __name__ == '__main__':
    unittest.main()
