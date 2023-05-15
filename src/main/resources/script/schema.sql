CREATE TABLE IF NOT EXISTS `Members` (
    `member_id`   VARCHAR(50)  NOT NULL,
    `name`        VARCHAR(50)  NOT NULL,
    `pwd`         VARCHAR(100) NOT NULL,

    PRIMARY KEY(`member_id`)
);

CREATE TABLE IF NOT EXISTS `Authoroties` (
    `member_id`   VARCHAR(50)  NOT NULL,
    `authority`   VARCHAR(50)  NOT NULL,

    PRIMARY KEY(`member_id`)
);

/* TODO #1: 기본 데이터 제공 */
MERGE INTO `Members` key ( `member_id` ) VALUES ( 'student', 'hark-sang', '12345' );
MERGE INTO `Members` key ( `member_id` ) VALUES ( 'teacher', 'sun-sang-nim', '67890' );

MERGE INTO `Authoroties` key ( `member_id` ) VALUES ( 'student', 'ROLE_STUDENT' );
MERGE INTO `Authoroties` key ( `member_id` ) VALUES ( 'teacher', 'ROLE_TEACHER' );
