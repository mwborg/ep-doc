
USE i360r_oas;

-- 学习计划
DROP TABLE IF EXISTS `t_study_plan`;
CREATE TABLE `t_study_plan` (
  `id` char(16) NOT NULL,
  `category_id` int(10) unsigned NOT NULL,
  `category_name` varchar(32) NOT NULL COMMENT '类别名称',
  `term_number` int(10) unsigned NOT NULL COMMENT '期数',
  `city_id` char(16) NOT NULL,
  `city_name` char(32) NOT NULL,
  `begin_date` date NOT NULL,
  `end_date` date NOT NULL,
  `create_time` datetime NOT NULL,
  `update_time` datetime NOT NULL,
  `created_by_id` char(16) NOT NULL,
  `created_by_name` varchar(32) NOT NULL,
  `updated_by_id` char(16) NOT NULL,
  `updated_by_name` varchar(32) NOT NULL,
  `is_national` char(1) NOT NULL COMMENT '是否全国学习计划',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_study_plan_location_category_term_number_national` (`city_id`, `category_id`, `term_number`, `is_national`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
